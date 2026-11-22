/* ZX Spectrum 48K / 128K + Pentagon BetaDisk 128 (TR-DOS): see zx.h. */
#pragma GCC optimize("O2")
#include "zx.h"
#include "z80.h"

#ifndef ZX_HOST
#include "hw.h"
#endif

#define LINE_T_48    224
#define LINES_48     312
#define FRAME_T_48   (LINE_T_48 * LINES_48)     /* 69888 */
#define PAPER_T_48   14336                      /* line 64 */

#define LINE_T_128   228
#define LINES_128    311
#define FRAME_T_128  (LINE_T_128 * LINES_128)   /* 70908 */
#define PAPER_T_128  14364                      /* line 63 */

#define INT_T        32
#define LD_BYTES     0x0556
#define SA_LD_RET    0x053F

#define CHANGES      4096
#define BLOCKS       1024
#define TRD_MAX      0xA0000u                   /* 640 KB (80 tracks x 2 sides x 16 sectors x 256 B) */
#define AUDIO_RING   4096

const u8 zx_rgb[16][3] = {
    {0x00, 0x00, 0x00}, {0x00, 0x00, 0xD7}, {0xD7, 0x00, 0x00}, {0xD7, 0x00, 0xD7},
    {0x00, 0xD7, 0x00}, {0x00, 0xD7, 0xD7}, {0xD7, 0xD7, 0x00}, {0xD7, 0xD7, 0xD7},
    {0x00, 0x00, 0x00}, {0x00, 0x00, 0xFF}, {0xFF, 0x00, 0x00}, {0xFF, 0x00, 0xFF},
    {0x00, 0xFF, 0x00}, {0x00, 0xFF, 0xFF}, {0xFF, 0xFF, 0x00}, {0xFF, 0xFF, 0xFF},
};

struct zx_mem {
    u8 ram[8][0x4000];                  /* 128 KB: 8 x 16 KB banks (48K uses banks 5, 2, 0) */
    u8 rom_builtin[2][0x4000];          /* Clean-room built-in ROM 0 (128K stub) & ROM 1 (48K BASIC + font) */
    u8 rom_trdos_buf[0x4000];           /* Clean-room built-in BetaDisk TR-DOS ROM */
    u8 rom_128_ext[2][0x4000];          /* Optional external 128.rom (32 KB) */
    u8 rom_trdos_ext[0x4000];           /* Optional external trdos.rom (16 KB) */
    u8 trd[TRD_MAX];                    /* Mounted .trd / unpacked .scl floppy image */
    u8 sec_buf[256];                    /* WD1793 sector data buffer */
    u8 cont[71200];                     /* Per-T-state ULA contention table */
    s32 change_t[CHANGES];
    u8 change_c[CHANGES];
    const u8 *block[BLOCKS];
    u32 block_n[BLOCKS];
    s16 audio_ring[AUDIO_RING];
};

#ifdef ZX_HOST
static struct zx_mem zx_host_mem;
#define M (&zx_host_mem)
#else
#define M ((struct zx_mem *)KSEG0(EMU_RAM_PHYS))
#endif

struct zx_ay {
    u8 reg_sel;
    u8 reg[16];
    u32 phase[3], noise_phase, env_phase;
    u8 out_bit[3];
    u32 lfsr;
    u8 env_step, env_vol, env_hold, env_att;
};

struct zx_wd1793 {
    u8 status, track, sector, data, sys;
    u8 cmd, drq, intrq;
    u8 side, drive;
    u16 buf_pos, buf_len;
    u8 writing;
    u32 write_off;
};

static struct z80 cpu;
static const u8 *ext_rom48;
static u8 has_ext_128, has_ext_trdos, using_builtin_rom;
static u8 is_128k, port_7ffd, trdos_active, has_trd, trd_dirty;
static s32 line_t, lines_n, frame_t, paper_t, top_line;
static u16 colour[16];
static u8 border, border_was, keys[8], kempston, ear_out;
static int changes;
static int blocks, block_at;
static u8 auto_load, builtin_tape_boot, builtin_trd_boot;
static u32 frames, cycles_hi;
static u16 *pic;
static char info[96];

/* Audio state */
static struct zx_ay ay;
static struct zx_wd1793 fdc;
static u32 sample_rate, audio_frac;
static s32 audio_last_cyc;
static int audio_count;
static s32 beep_dc;

static const s16 ay_vol_tab[16] = {
       0,   140,   198,   280,   396,   560,   792,  1120,
    1584,  2240,  3168,  4480,  6336,  8960, 12672, 16000
};

/* Clean 8x8 ASCII font (0x20..0x7F) placed at $3D00..$3FFF in built-in ROM */
static const u8 zx_font96[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x00,0x10,0x10,0x10,0x10,0x00,0x10,0x00},
    {0x00,0x24,0x24,0x00,0x00,0x00,0x00,0x00}, {0x00,0x24,0x7E,0x24,0x24,0x7E,0x24,0x00},
    {0x00,0x08,0x3E,0x28,0x3E,0x0A,0x3E,0x08}, {0x00,0x62,0x64,0x08,0x10,0x26,0x46,0x00},
    {0x00,0x10,0x28,0x10,0x2A,0x44,0x3A,0x00}, {0x00,0x08,0x10,0x00,0x00,0x00,0x00,0x00},
    {0x00,0x04,0x08,0x08,0x08,0x08,0x04,0x00}, {0x00,0x20,0x10,0x10,0x10,0x10,0x20,0x00},
    {0x00,0x00,0x14,0x08,0x3E,0x08,0x14,0x00}, {0x00,0x00,0x08,0x08,0x3E,0x08,0x08,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x08,0x08,0x10}, {0x00,0x00,0x00,0x00,0x3E,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00}, {0x00,0x00,0x02,0x04,0x08,0x10,0x20,0x00},
    {0x00,0x3C,0x46,0x4A,0x52,0x62,0x3C,0x00}, {0x00,0x18,0x28,0x08,0x08,0x08,0x3E,0x00},
    {0x00,0x3C,0x42,0x02,0x3C,0x40,0x7E,0x00}, {0x00,0x3C,0x42,0x0C,0x02,0x42,0x3C,0x00},
    {0x00,0x08,0x18,0x28,0x48,0x7E,0x08,0x00}, {0x00,0x7E,0x40,0x7C,0x02,0x42,0x3C,0x00},
    {0x00,0x3C,0x40,0x7C,0x42,0x42,0x3C,0x00}, {0x00,0x7E,0x02,0x04,0x08,0x10,0x10,0x00},
    {0x00,0x3C,0x42,0x3C,0x42,0x42,0x3C,0x00}, {0x00,0x3C,0x42,0x42,0x3E,0x02,0x3C,0x00},
    {0x00,0x00,0x00,0x10,0x00,0x00,0x10,0x00}, {0x00,0x00,0x10,0x00,0x00,0x10,0x10,0x20},
    {0x00,0x00,0x04,0x08,0x10,0x08,0x04,0x00}, {0x00,0x00,0x00,0x3E,0x00,0x3E,0x00,0x00},
    {0x00,0x00,0x10,0x08,0x04,0x08,0x10,0x00}, {0x00,0x3C,0x42,0x04,0x08,0x00,0x08,0x00},
    {0x00,0x3C,0x4A,0x56,0x5E,0x40,0x3C,0x00}, {0x00,0x3C,0x42,0x42,0x7E,0x42,0x42,0x00},
    {0x00,0x7C,0x42,0x7C,0x42,0x42,0x7C,0x00}, {0x00,0x3C,0x42,0x40,0x40,0x42,0x3C,0x00},
    {0x00,0x78,0x44,0x42,0x42,0x44,0x78,0x00}, {0x00,0x7E,0x40,0x7C,0x40,0x40,0x7E,0x00},
    {0x00,0x7E,0x40,0x7C,0x40,0x40,0x40,0x00}, {0x00,0x3C,0x42,0x40,0x4E,0x42,0x3C,0x00},
    {0x00,0x42,0x42,0x7E,0x42,0x42,0x42,0x00}, {0x00,0x3E,0x08,0x08,0x08,0x08,0x3E,0x00},
    {0x00,0x02,0x02,0x02,0x42,0x42,0x3C,0x00}, {0x00,0x44,0x48,0x70,0x48,0x44,0x42,0x00},
    {0x00,0x40,0x40,0x40,0x40,0x40,0x7E,0x00}, {0x00,0x42,0x66,0x5A,0x42,0x42,0x42,0x00},
    {0x00,0x42,0x62,0x52,0x4A,0x46,0x42,0x00}, {0x00,0x3C,0x42,0x42,0x42,0x42,0x3C,0x00},
    {0x00,0x7C,0x42,0x42,0x7C,0x40,0x40,0x00}, {0x00,0x3C,0x42,0x42,0x52,0x4A,0x3C,0x00},
    {0x00,0x7C,0x42,0x42,0x7C,0x44,0x42,0x00}, {0x00,0x3C,0x40,0x3C,0x02,0x42,0x3C,0x00},
    {0x00,0xFE,0x10,0x10,0x10,0x10,0x10,0x00}, {0x00,0x42,0x42,0x42,0x42,0x42,0x3C,0x00},
    {0x00,0x42,0x42,0x42,0x42,0x24,0x18,0x00}, {0x00,0x42,0x42,0x42,0x5A,0x66,0x42,0x00},
    {0x00,0x42,0x24,0x18,0x18,0x24,0x42,0x00}, {0x00,0x82,0x44,0x28,0x10,0x10,0x10,0x00},
    {0x00,0x7E,0x04,0x08,0x10,0x20,0x7E,0x00}, {0x00,0x0E,0x08,0x08,0x08,0x08,0x0E,0x00},
    {0x00,0x00,0x40,0x20,0x10,0x08,0x04,0x00}, {0x00,0x70,0x10,0x10,0x10,0x10,0x70,0x00},
    {0x00,0x10,0x38,0x54,0x10,0x10,0x10,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF},
    {0x00,0x1C,0x22,0x78,0x20,0x20,0x7E,0x00}, {0x00,0x00,0x38,0x04,0x3C,0x44,0x3C,0x00},
    {0x00,0x20,0x20,0x3C,0x22,0x22,0x3C,0x00}, {0x00,0x00,0x1C,0x20,0x20,0x20,0x1C,0x00},
    {0x00,0x04,0x04,0x3C,0x44,0x44,0x3C,0x00}, {0x00,0x00,0x38,0x44,0x78,0x40,0x3C,0x00},
    {0x00,0x0C,0x10,0x18,0x10,0x10,0x10,0x00}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x38},
    {0x00,0x40,0x40,0x78,0x44,0x44,0x44,0x00}, {0x00,0x10,0x00,0x30,0x10,0x10,0x38,0x00},
    {0x00,0x04,0x00,0x04,0x04,0x04,0x24,0x18}, {0x00,0x20,0x28,0x30,0x30,0x28,0x24,0x00},
    {0x00,0x10,0x10,0x10,0x10,0x10,0x0C,0x00}, {0x00,0x00,0x68,0x54,0x54,0x54,0x54,0x00},
    {0x00,0x00,0x78,0x44,0x44,0x44,0x44,0x00}, {0x00,0x00,0x38,0x44,0x44,0x44,0x38,0x00},
    {0x00,0x00,0x78,0x44,0x44,0x78,0x40,0x40}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x06},
    {0x00,0x00,0x1C,0x20,0x20,0x20,0x20,0x00}, {0x00,0x00,0x38,0x40,0x38,0x04,0x78,0x00},
    {0x00,0x10,0x38,0x10,0x10,0x10,0x0C,0x00}, {0x00,0x00,0x44,0x44,0x44,0x44,0x38,0x00},
    {0x00,0x00,0x44,0x44,0x28,0x28,0x10,0x00}, {0x00,0x00,0x44,0x54,0x54,0x54,0x28,0x00},
    {0x00,0x00,0x44,0x28,0x10,0x28,0x44,0x00}, {0x00,0x00,0x44,0x44,0x44,0x3C,0x04,0x38},
    {0x00,0x00,0x7C,0x08,0x10,0x20,0x7C,0x00}, {0x00,0x0E,0x08,0x30,0x08,0x08,0x0E,0x00},
    {0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x00}, {0x00,0x70,0x10,0x0C,0x10,0x10,0x70,0x00},
    {0x00,0x14,0x28,0x00,0x00,0x00,0x00,0x00}, {0x3C,0x42,0x99,0xA1,0xA1,0x99,0x42,0x3C}
};

/* ---- Audio synthesis (ULA Beeper + AY-3-8912 PSG) ---- */
static void audio_step(u32 tstates)
{
    if (!sample_rate || !tstates)
        return;
    u32 cpu_hz = is_128k ? 3546900u : 3500000u;
    u32 count = 0;
    while (tstates) {
        u32 chunk = tstates > 16000u ? 16000u : tstates;
        tstates -= chunk;
        u32 num = chunk * sample_rate + audio_frac;
        count += num / cpu_hz;
        audio_frac = num % cpu_hz;
    }
    if (!count)
        return;

    /* AY clock on 128K = 1.7734 MHz / 16 = 110837.5 Hz -> *256 = 28374400 */
    u32 ay_step = 28374400u / sample_rate;
    s32 beep_raw = ((ear_out & 0x10u) ? 5500 : 0) + ((ear_out & 0x08u) ? 1200 : 0);

    while (count--) {
        /* High-pass DC blocker on beeper so steady EAR state doesn't hold DC offset */
        beep_dc += (beep_raw - (beep_dc >> 10));
        s32 mix = beep_raw - (beep_dc >> 10);

        /* AY-3-8912 */
        u32 ep = (u32)ay.reg[11] | ((u32)ay.reg[12] << 8);
        if (!ep) ep = 1u;
        u32 ep8 = ep << 8;
        ay.env_phase += ay_step;
        while (ay.env_phase >= ep8) {
            ay.env_phase -= ep8;
            if (!ay.env_hold) {
                ay.env_step++;
                if (ay.env_step >= 16) {
                    ay.env_step = 0;
                    u8 sh = ay.reg[13] & 0x0Fu;
                    if (!(sh & 0x08u)) {
                        ay.env_att = 0;
                        ay.env_hold = 1;
                    } else {
                        if (sh & 0x02u) ay.env_att ^= 0x0Fu;
                        if (sh & 0x01u) { ay.env_hold = 1; ay.env_step = 15; }
                    }
                }
            }
            ay.env_vol = (ay.env_step ^ ay.env_att) & 15u;
        }

        u32 np = ay.reg[6] & 0x1Fu;
        if (!np) np = 1u;
        u32 np8 = np << 8;
        ay.noise_phase += ay_step;
        while (ay.noise_phase >= np8) {
            ay.noise_phase -= np8;
            u32 fb = ((ay.lfsr >> 0) ^ (ay.lfsr >> 3)) & 1u;
            ay.lfsr = (ay.lfsr >> 1) | (fb << 16);
        }

        u8 mixer = ay.reg[7];
        for (int ch = 0; ch < 3; ch++) {
            u32 tp = (u32)ay.reg[ch * 2] | (((u32)ay.reg[ch * 2 + 1] & 0x0Fu) << 8);
            if (!tp) tp = 1u;
            u32 tp8 = tp << 8;
            ay.phase[ch] += ay_step;
            while (ay.phase[ch] >= tp8) {
                ay.phase[ch] -= tp8;
                ay.out_bit[ch] ^= 1u;
            }
            int t_ok = (mixer & (1u << ch)) || ay.out_bit[ch];
            int n_ok = (mixer & (8u << ch)) || (ay.lfsr & 1u);
            u8 vr = ay.reg[8 + ch];
            u8 vol = (vr & 0x10u) ? ay.env_vol : (vr & 0x0Fu);
            if (vol && t_ok && n_ok)
                mix += ay_vol_tab[vol & 15u] >> 1;
        }

        if (mix > 32767) mix = 32767;
        if (mix < -32768) mix = -32768;
        if (audio_count < AUDIO_RING)
            M->audio_ring[audio_count++] = (s16)mix;
    }
}

static void audio_catch_up(void)
{
    if (!sample_rate)
        return;
    s32 now = cpu.cycles;
    if (now > audio_last_cyc) {
        audio_step((u32)(now - audio_last_cyc));
        audio_last_cyc = now;
    }
}

static void ay_write_reg(u8 r, u8 v)
{
    if (r >= 16)
        return;
    audio_catch_up();
    static const u8 mask[16] = {
        0xFF, 0x0F, 0xFF, 0x0F, 0xFF, 0x0F, 0x1F, 0xFF,
        0x1F, 0x1F, 0x1F, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF
    };
    ay.reg[r] = v & mask[r];
    if (r == 13) {
        ay.env_phase = 0;
        ay.env_step = 0;
        ay.env_hold = 0;
        ay.env_att = (v & 0x04u) ? 0x0Fu : 0x00u;
        ay.env_vol = ay.env_att ^ 0x0Fu;
    }
}

/* ---- Keyboard ---- */
#define K(row, bit) ((row) * 8 + (bit))
#define CAPS 0x40
#define SYM  0x80
#define NONE 0xFF

static u8 char_keys(int ch)
{
    static const u8 letters[26] = {K(1, 0), K(7, 4), K(0, 3), K(1, 2), K(2, 2), K(1, 3), K(1, 4), K(6, 4), K(5, 2),
                                   K(6, 3), K(6, 2), K(6, 1), K(7, 2), K(7, 3), K(5, 1), K(5, 0), K(2, 0), K(2, 3),
                                   K(1, 1), K(2, 4), K(5, 3), K(0, 4), K(2, 1), K(0, 2), K(5, 4), K(0, 1)};
    static const u8 digits[10] = {K(4, 0), K(3, 0), K(3, 1), K(3, 2), K(3, 3), K(3, 4), K(4, 4), K(4, 3), K(4, 2),
                                  K(4, 1)};
    static const struct {
        char ch;
        u8 keys;
    } symbols[] = {
        {'!', SYM | K(3, 0)}, {'@', SYM | K(3, 1)}, {'#', SYM | K(3, 2)}, {'$', SYM | K(3, 3)}, {'%', SYM | K(3, 4)},
        {'&', SYM | K(4, 4)}, {'\'', SYM | K(4, 3)}, {'(', SYM | K(4, 2)}, {')', SYM | K(4, 1)}, {'_', SYM | K(4, 0)},
        {'<', SYM | K(2, 3)}, {'>', SYM | K(2, 4)}, {';', SYM | K(5, 1)}, {'"', SYM | K(5, 0)}, {'^', SYM | K(6, 4)},
        {'-', SYM | K(6, 3)}, {'+', SYM | K(6, 2)}, {'=', SYM | K(6, 1)}, {':', SYM | K(0, 1)}, {'`', SYM | K(0, 2)},
        {'?', SYM | K(0, 3)}, {'/', SYM | K(0, 4)}, {'*', SYM | K(7, 4)}, {',', SYM | K(7, 3)}, {'.', SYM | K(7, 2)},
        {' ', K(7, 0)}, {'\n', K(6, 0)}, {'\r', K(6, 0)}, {8, CAPS | K(4, 0)}, {127, CAPS | K(4, 0)},
    };
    if (ch >= 'a' && ch <= 'z')
        return letters[ch - 'a'];
    if (ch >= 'A' && ch <= 'Z')
        return CAPS | letters[ch - 'A'];
    if (ch >= '0' && ch <= '9')
        return digits[ch - '0'];
    for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++)
        if (symbols[i].ch == ch)
            return symbols[i].keys;
    return NONE;
}

static void press(u8 matrix[8], u8 k)
{
    if (k == NONE)
        return;
    matrix[(k & 0x3F) >> 3] |= (u8)(1u << (k & 7));
    if (k & CAPS)
        matrix[0] |= 0x01;
    if (k & SYM)
        matrix[7] |= 0x02;
}

void zx_keys_from_hid(const u8 *usages, int n, u8 matrix[8])
{
    static const char plain[] = "-=[]\\#;'`,./", shifted[] = "_+{}|~:\"~<>?";
    static const char digit_shifted[] = "!@#$%^&*()";
    int shift = 0, symbol_used = 0;
    for (int i = 0; i < 8; i++)
        matrix[i] = 0;
    for (int i = 0; i < n; i++)
        if (usages[i] == 0xE1 || usages[i] == 0xE5)
            shift = 1;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u >= 0x04 && u <= 0x1D)
            press(matrix, char_keys('a' + (u - 0x04)));
        else if (u >= 0x1E && u <= 0x27) {
            int d = u == 0x27 ? 0 : u - 0x1D;
            if (shift) {
                press(matrix, char_keys(digit_shifted[(d + 9) % 10]));
                symbol_used = 1;
            } else {
                press(matrix, char_keys('0' + d));
            }
        } else if (u == 0x28 || u == 0x58)
            press(matrix, K(6, 0));
        else if (u == 0x2C)
            press(matrix, K(7, 0));
        else if (u == 0x2A || u == 0x4C)
            press(matrix, CAPS | K(4, 0));
        else if (u == 0x29)
            press(matrix, CAPS | K(7, 0));
        else if (u >= 0x4F && u <= 0x52) {
            static const u8 arrow[4] = {K(4, 2), K(3, 4), K(4, 4), K(4, 3)};
            press(matrix, CAPS | arrow[u - 0x4F]);
        } else if (u >= 0x2D && u <= 0x38) {
            u8 k = char_keys((shift ? shifted : plain)[u - 0x2D]);
            press(matrix, k);
            if (k != NONE)
                symbol_used = 1;
        } else if (u == 0xE0 || u == 0xE2 || u == 0xE4 || u == 0xE6)
            matrix[7] |= 0x02;
    }
    if (shift && !symbol_used)
        matrix[0] |= 0x01;
}

static char queue[256];
static int q_head, q_tail, q_frame;

void zx_type(const char *text)
{
    while (*text) {
        int next = (q_tail + 1) & 255;
        if (next == q_head)
            break;
        queue[q_tail] = *text++;
        q_tail = next;
    }
}

int zx_typing(void)
{
    return (q_tail - q_head) & 255;
}

static void typed(u8 matrix[8])
{
    if (q_head == q_tail)
        return;
    if (q_frame < 3)
        press(matrix, char_keys(queue[q_head]));
    if (++q_frame == 9) {
        q_frame = 0;
        q_head = (q_head + 1) & 255;
    }
}

/* ---- Memory Map & BetaDisk 128 Paging ---- */
static const u8 *active_rom48(void)
{
    if (ext_rom48)
        return ext_rom48;
    if (has_ext_128)
        return M->rom_128_ext[1];
    return M->rom_builtin[1];
}

static const u8 *active_rom0(void)
{
    if (has_ext_128)
        return M->rom_128_ext[0];
    if (ext_rom48)
        return ext_rom48;
    return M->rom_builtin[0];
}

static const u8 *active_trdos(void)
{
    return has_ext_trdos ? M->rom_trdos_ext : M->rom_trdos_buf;
}

static void rebuild_map(void)
{
    const u8 *r0 = trdos_active ? active_trdos() : ((port_7ffd & 0x10u) ? active_rom48() : active_rom0());
    for (int i = 0; i < 16; i++) {
        cpu.rd[i] = (u8 *)r0 + (i << 10);
        cpu.wr[i] = 0;
        cpu.op[i] = 0;
    }
    /* When BetaDisk has a disk mounted and ROM 1 (48K) is active, intercept page 15 ($3C00..$3FFF)
       reads so M1 fetches at $3D00..$3DFF page in TR-DOS while data reads still return the font. */
    int rom1_sel = (port_7ffd & 0x10u) || !has_ext_128;
    if (has_trd && !trdos_active && rom1_sel)
        cpu.rd[15] = 0;

    u8 *b5 = M->ram[5];
    u8 *b2 = M->ram[2];
    u8 *btop = M->ram[port_7ffd & 7u];

    for (int i = 0; i < 16; i++) {
        cpu.rd[16 + i] = trdos_active ? 0 : (b5 + (i << 10));
        cpu.wr[16 + i] = b5 + (i << 10);
        cpu.rd[32 + i] = trdos_active ? 0 : (b2 + (i << 10));
        cpu.wr[32 + i] = b2 + (i << 10);
        cpu.rd[48 + i] = trdos_active ? 0 : (btop + (i << 10));
        cpu.wr[48 + i] = btop + (i << 10);
    }
}

static inline u8 ram_peek_fast(u16 a)
{
    if (a < 0x4000u) {
        const u8 *r0 = trdos_active ? active_trdos() : ((port_7ffd & 0x10u) ? active_rom48() : active_rom0());
        return r0[a];
    }
    if (a < 0x8000u) return M->ram[5][a - 0x4000u];
    if (a < 0xC000u) return M->ram[2][a - 0x8000u];
    return M->ram[port_7ffd & 7u][a - 0xC000u];
}

static inline void ram_poke_fast(u16 a, u8 v)
{
    if (a < 0x4000u) return;
    if (a < 0x8000u)      M->ram[5][a - 0x4000u] = v;
    else if (a < 0xC000u) M->ram[2][a - 0x8000u] = v;
    else                  M->ram[port_7ffd & 7u][a - 0xC000u] = v;
}

static u8 zx_mem_read(struct z80 *c, u16 a)
{
    if (!trdos_active && a >= 0x3C00u && a < 0x4000u) {
        /* M1 fetch sets PC = a + 1 before calling read() */
        if (has_trd && a >= 0x3D00u && a < 0x3E00u && c->pc.w == (u16)(a + 1u)) {
            trdos_active = 1;
            rebuild_map();
            return active_trdos()[a];
        }
        const u8 *r0 = (port_7ffd & 0x10u) ? active_rom48() : active_rom0();
        return r0[a];
    }
    if (trdos_active && a >= 0x4000u) {
        if (c->pc.w == (u16)(a + 1u)) {
            trdos_active = 0;
            rebuild_map();
        }
        return ram_peek_fast(a);
    }
    return ram_peek_fast(a);
}

static void zx_mem_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    ram_poke_fast(a, v);
}

/* ---- BetaDisk WD1793 FDC + Clean-Room TR-DOS #3D13 ---- */
static u32 trd_offset(u8 cyl, u8 side, u8 sec1)
{
    u32 trk = (u32)cyl * 2u + (side & 1u);
    u32 s = (sec1 >= 1u && sec1 <= 16u) ? (u32)(sec1 - 1u) : 0u;
    u32 off = (trk * 16u + s) * 256u;
    return off < TRD_MAX ? off : 0u;
}

static u8 wd_read(u8 port)
{
    switch (port) {
    case 0x1F:                          /* Status */
        fdc.intrq = 0;
        return fdc.status;
    case 0x3F:
        return fdc.track;
    case 0x5F:
        return fdc.sector;
    case 0x7F:
        if (fdc.drq && !fdc.writing && fdc.buf_pos < fdc.buf_len) {
            fdc.data = M->sec_buf[fdc.buf_pos++];
            if (fdc.buf_pos >= fdc.buf_len) {
                if ((fdc.cmd & 0xF0u) == 0x90u && fdc.sector < 16u) {
                    fdc.sector++;
                    u32 off = trd_offset(fdc.track, fdc.side, fdc.sector);
                    for (int i = 0; i < 256; i++)
                        M->sec_buf[i] = M->trd[off + (u32)i];
                    fdc.buf_pos = 0;
                } else {
                    fdc.drq = 0;
                    fdc.status = 0x00u;
                    fdc.intrq = 1;
                }
            }
        }
        return fdc.data;
    case 0xFF:                          /* BetaDisk system status: bit 7 INTRQ, bit 6 DRQ */
        return (u8)((fdc.intrq ? 0x80u : 0x00u) | (fdc.drq ? 0x40u : 0x00u) | 0x3Fu);
    }
    return 0xFFu;
}

static void wd_write(u8 port, u8 v)
{
    switch (port) {
    case 0x1F: {                        /* Command */
        fdc.cmd = v;
        fdc.drq = 0;
        fdc.writing = 0;
        u8 hi = v & 0xF0u;
        if (hi == 0x00u) {              /* RESTORE */
            fdc.track = 0;
            fdc.status = 0x04u;         /* TR00 */
            fdc.intrq = 1;
        } else if (hi == 0x10u) {       /* SEEK */
            fdc.track = fdc.data < 80u ? fdc.data : 79u;
            fdc.status = fdc.track == 0 ? 0x04u : 0x00u;
            fdc.intrq = 1;
        } else if (hi >= 0x20u && hi <= 0x70u) { /* STEP / STEP-IN / STEP-OUT */
            int dir = (hi >= 0x60u) ? -1 : 1;
            int nt = (int)fdc.track + dir;
            if (nt < 0) nt = 0;
            if (nt > 79) nt = 79;
            if ((v & 0x10u) || hi >= 0x40u)
                fdc.track = (u8)nt;
            fdc.status = fdc.track == 0 ? 0x04u : 0x00u;
            fdc.intrq = 1;
        } else if (hi == 0x80u || hi == 0x90u) { /* READ SECTOR(S) */
            if (!has_trd || fdc.drive != 0 || fdc.sector < 1u || fdc.sector > 16u) {
                fdc.status = 0x10u;     /* RNF */
                fdc.intrq = 1;
            } else {
                u32 off = trd_offset(fdc.track, fdc.side, fdc.sector);
                for (int i = 0; i < 256; i++)
                    M->sec_buf[i] = M->trd[off + (u32)i];
                fdc.buf_pos = 0;
                fdc.buf_len = 256;
                fdc.data = M->sec_buf[0];
                fdc.drq = 1;
                fdc.status = 0x03u;     /* BUSY | DRQ */
                fdc.intrq = 0;
            }
        } else if (hi == 0xA0u || hi == 0xB0u) { /* WRITE SECTOR(S) */
            if (!has_trd || fdc.drive != 0 || fdc.sector < 1u || fdc.sector > 16u) {
                fdc.status = 0x10u;
                fdc.intrq = 1;
            } else {
                fdc.write_off = trd_offset(fdc.track, fdc.side, fdc.sector);
                fdc.buf_pos = 0;
                fdc.buf_len = 256;
                fdc.writing = 1;
                fdc.drq = 1;
                fdc.status = 0x03u;
                fdc.intrq = 0;
            }
        } else if (hi == 0xC0u) {       /* READ ADDRESS */
            M->sec_buf[0] = fdc.track;
            M->sec_buf[1] = fdc.side;
            M->sec_buf[2] = 1;
            M->sec_buf[3] = 1;
            M->sec_buf[4] = 0;
            M->sec_buf[5] = 0;
            fdc.sector = fdc.track;
            fdc.buf_pos = 0;
            fdc.buf_len = 6;
            fdc.drq = 1;
            fdc.status = 0x03u;
            fdc.intrq = 0;
        } else if (hi == 0xD0u) {       /* FORCE INTERRUPT */
            fdc.drq = 0;
            fdc.writing = 0;
            fdc.status = (fdc.track == 0) ? 0x04u : 0x00u;
            fdc.intrq = (v & 0x0Fu) ? 1u : 0u;
        } else {                        /* READ/WRITE TRACK */
            fdc.status = 0x00u;
            fdc.intrq = 1;
        }
        break;
    }
    case 0x3F: fdc.track = v; break;
    case 0x5F: fdc.sector = v; break;
    case 0x7F:
        fdc.data = v;
        if (fdc.drq && fdc.writing && fdc.buf_pos < fdc.buf_len) {
            M->sec_buf[fdc.buf_pos++] = v;
            if (fdc.buf_pos >= fdc.buf_len) {
                for (u32 i = 0; i < 256u && fdc.write_off + i < TRD_MAX; i++)
                    M->trd[fdc.write_off + i] = M->sec_buf[i];
                trd_dirty = 1;
                if ((fdc.cmd & 0xF0u) == 0xB0u && fdc.sector < 16u) {
                    fdc.sector++;
                    fdc.write_off = trd_offset(fdc.track, fdc.side, fdc.sector);
                    fdc.buf_pos = 0;
                } else {
                    fdc.drq = 0;
                    fdc.writing = 0;
                    fdc.status = 0x00u;
                    fdc.intrq = 1;
                }
            }
        }
        break;
    case 0xFF:
        fdc.sys = v;
        fdc.drive = v & 3u;
        fdc.side = (v & 0x10u) ? 0u : 1u;   /* bit 4 active-low side 1 select */
        if (!(v & 0x04u)) {                 /* active-low /RESET */
            fdc.track = 0;
            fdc.sector = 1;
            fdc.status = 0x04u;
            fdc.drq = 0;
            fdc.intrq = 0;
            fdc.writing = 0;
        }
        break;
    }
}

/* Clean-room TR-DOS #3D13 service dispatcher (when no external trdos.rom is present) */
static void trdos_hle_3d13(void)
{
    u8 fn = cpu.bc.b.l;
    switch (fn) {
    case 0x00:                          /* Reset VG93 */
    case 0x01:                          /* Select drive A */
    case 0x18:                          /* Setup disk */
        fdc.drive = cpu.af.b.h & 3u;
        ram_poke_fast(0x5CF6u, fdc.drive);
        cpu.af.b.l &= (u8)~Z80_FC;
        break;
    case 0x02: {                        /* Seek logical track A */
        u8 lt = cpu.af.b.h;
        fdc.track = lt >> 1;
        fdc.side = lt & 1u;
        break;
    }
    case 0x05:                          /* Read B sectors from track D, sector E into HL */
    case 0x06: {                        /* Write B sectors from HL to track D, sector E */
        u8 cnt = cpu.bc.b.h;
        u8 trk = cpu.de.b.h;
        u8 sec = cpu.de.b.l & 15u;
        u16 dst = cpu.hl.w;
        for (u32 s = 0; s < cnt; s++) {
            u32 lsec = (u32)trk * 16u + (u32)sec;
            u32 off = lsec * 256u;
            for (u32 i = 0; i < 256u; i++) {
                if (fn == 0x05) {
                    u8 val = (has_trd && off + i < TRD_MAX) ? M->trd[off + i] : 0;
                    ram_poke_fast((u16)(dst + i), val);
                } else if (has_trd && off + i < TRD_MAX) {
                    M->trd[off + i] = ram_peek_fast((u16)(dst + i));
                    trd_dirty = 1;
                }
            }
            dst = (u16)(dst + 256u);
            sec++;
            if (sec >= 16u) {
                sec = 0;
                trk++;
            }
        }
        /* TR-DOS updates ($5CF4/$5CF5) with next sector & track, and DE as well */
        ram_poke_fast(0x5CF4u, sec);
        ram_poke_fast(0x5CF5u, trk);
        cpu.de.b.l = sec;
        cpu.de.b.h = trk;
        fdc.track = trk >> 1;
        fdc.side = trk & 1u;
        fdc.sector = (u8)(sec + 1u);
        cpu.af.b.l &= (u8)~Z80_FC;
        break;
    }
    case 0x08: {                        /* Read catalog entry A into #5CDD */
        u32 idx = cpu.af.b.h & 127u;
        for (u32 i = 0; i < 16u; i++)
            ram_poke_fast((u16)(0x5CDDu + i), M->trd[idx * 16u + i]);
        break;
    }
    case 0x09: {                        /* Write #5CDD to catalog entry A */
        u32 idx = cpu.af.b.h & 127u;
        for (u32 i = 0; i < 16u; i++)
            M->trd[idx * 16u + i] = ram_peek_fast((u16)(0x5CDDu + i));
        trd_dirty = 1;
        break;
    }
    case 0x0A: {                        /* Find file matching #5CDD -> C = index or 0xFF */
        u8 found = 0xFFu;
        u8 nlen = ram_peek_fast(0x5CE6u);
        if (!nlen || nlen > 9u) nlen = 9u;
        for (u32 idx = 0; idx < 128u; idx++) {
            const u8 *ent = M->trd + idx * 16u;
            if (ent[0] == 0x00u) break;
            if (ent[0] == 0x01u) continue;
            int match = 1;
            for (u32 k = 0; k < nlen; k++) {
                if (ent[k] != ram_peek_fast((u16)(0x5CDDu + k))) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                found = (u8)idx;
                break;
            }
        }
        cpu.bc.b.l = found;
        if (found == 0xFFu) cpu.af.b.l &= (u8)~Z80_FZ;
        else                cpu.af.b.l |= Z80_FZ;
        break;
    }
    case 0x0E: {                        /* Load file matching #5CDD */
        u8 mode = cpu.af.b.h;
        u16 load_hl = cpu.hl.w;
        int found = -1;
        for (int idx = 0; idx < 128; idx++) {
            const u8 *ent = M->trd + idx * 16;
            if (ent[0] == 0x00u) break;
            if (ent[0] == 0x01u) continue;
            int ok = 1;
            for (int k = 0; k < 8; k++)
                if (ent[k] != ram_peek_fast((u16)(0x5CDDu + k))) { ok = 0; break; }
            if (ok) { found = idx; break; }
        }
        if (found >= 0) {
            const u8 *ent = M->trd + found * 16;
            u16 start = (u16)(ent[9] | ((u16)ent[10] << 8));
            u16 blen  = (u16)(ent[11] | ((u16)ent[12] << 8));
            u8  slen  = ent[13];
            u8  sec   = ent[14] & 15u;
            u8  trk   = ent[15];
            u16 dst   = (mode == 0) ? start : load_hl;
            u32 total = (mode == 3 && cpu.de.w) ? cpu.de.w : (blen ? blen : (u32)slen * 256u);
            u32 off   = ((u32)trk * 16u + sec) * 256u;
            for (u32 i = 0; i < total && off + i < TRD_MAX; i++)
                ram_poke_fast((u16)(dst + i), M->trd[off + i]);
            u32 end_sec = (u32)trk * 16u + sec + slen;
            ram_poke_fast(0x5CF4u, (u8)(end_sec & 15u));
            ram_poke_fast(0x5CF5u, (u8)(end_sec >> 4));
        }
        break;
    }
    case 0x13:                          /* Copy 16 bytes HL -> #5CDD */
        for (u32 i = 0; i < 16u; i++)
            ram_poke_fast((u16)(0x5CDDu + i), ram_peek_fast((u16)(cpu.hl.w + i)));
        break;
    case 0x14:                          /* Copy 16 bytes #5CDD -> HL */
        for (u32 i = 0; i < 16u; i++)
            ram_poke_fast((u16)(cpu.hl.w + i), ram_peek_fast((u16)(0x5CDDu + i)));
        break;
    }
}

/* ---- Built-in Clean-Room BASIC / Tape / TR-DOS Booter ---- */
static u16 parse_basic_int(const u8 *p, u32 len, u32 *pos)
{
    u32 i = *pos;
    while (i < len && p[i] == ' ') i++;
    /* VAL "12345" */
    if (i < len && p[i] == 0xB0u) {
        i++;
        while (i < len && p[i] == ' ') i++;
        if (i < len && p[i] == '"') {
            i++;
            u32 v = 0;
            while (i < len && p[i] >= '0' && p[i] <= '9')
                v = v * 10u + (u32)(p[i++] - '0');
            if (i < len && p[i] == '"') i++;
            *pos = i;
            return (u16)v;
        }
    }
    /* PEEK a + 256 * PEEK b (e.g., PEEK 23635 + 256 * PEEK 23636 + offset) */
    if (i < len && p[i] == 0xBEu) {
        i++;
        u16 a1 = parse_basic_int(p, len, &i);
        u32 val = ram_peek_fast(a1);
        while (i < len && (p[i] == '+' || p[i] == '*')) {
            u8 op = p[i++];
            u16 rhs = parse_basic_int(p, len, &i);
            if (op == '+') {
                if (i < len && p[i] == '*') {
                    i++;
                    u16 m2 = parse_basic_int(p, len, &i);
                    val += (u32)rhs * (u32)m2;
                } else {
                    val += rhs;
                }
            } else {
                val *= rhs;
            }
        }
        *pos = i;
        return (u16)val;
    }
    /* Standard ASCII digits optionally followed by 0x0E + 5-byte Spectrum float */
    u32 v = 0;
    int had = 0;
    while (i < len && p[i] >= '0' && p[i] <= '9') {
        v = v * 10u + (u32)(p[i++] - '0');
        had = 1;
    }
    if (i + 5 < len && p[i] == 0x0Eu) {
        if (p[i + 1] == 0x00u && (p[i + 2] == 0x00u || p[i + 2] == 0xFFu)) {
            u16 iv = (u16)(p[i + 3] | ((u16)p[i + 4] << 8));
            if (!had) v = iv;
        }
        i += 6;
    }
    *pos = i;
    return (u16)v;
}

static void zx_out(struct z80 *c, u16 port, u8 v);

static void hle_boot_tape(void)
{
    u16 last_code_addr = 0;
    u16 usr_target = 0;
    u16 sp_target = 0xFF40u;

    /* Load BASIC block if first block is a Program header (flag 0x00, type 0) */
    if (blocks >= 2 && M->block_n[0] >= 19 && M->block[0][0] == 0x00u && M->block[0][1] == 0x00u &&
        M->block_n[1] >= 2 && M->block[1][0] == 0xFFu) {
        const u8 *bas = M->block[1] + 1;
        u32 bas_len = M->block_n[1] - 2u;
        u16 prog_len = (u16)(M->block[0][12] | ((u16)M->block[0][13] << 8));
        if (prog_len > bas_len) prog_len = (u16)bas_len;

        /* Copy BASIC into $5CCB (PROG) in case loader executes REM machine code at $5CCB+5! */
        ram_poke_fast(0x5C53u, 0xCBu);
        ram_poke_fast(0x5C54u, 0x5Cu);
        for (u32 i = 0; i < bas_len && 0x5CCBu + i < 0xFF00u; i++)
            ram_poke_fast((u16)(0x5CCBu + i), bas[i]);
        block_at = 2;

        /* Walk tokenized BASIC lines */
        u32 pos = 0;
        while (pos + 4 <= prog_len && !usr_target) {
            u16 llen = (u16)(bas[pos + 2] | ((u16)bas[pos + 3] << 8));
            pos += 4;
            u32 lend = pos + llen;
            if (lend > prog_len) lend = prog_len;
            u32 i = pos;
            while (i < lend) {
                u8 tk = bas[i++];
                if (tk == 0xEAu)        /* REM: rest of line is comment / machine code */
                    break;
                if (tk == 0x0Eu) { i += 5; continue; }
                if (tk == 0xFDu) {      /* CLEAR <addr> */
                    u16 a = parse_basic_int(bas, lend, &i);
                    if (a >= 0x5D00u) sp_target = a;
                } else if (tk == 0xE7u) { /* BORDER <n> */
                    u16 b = parse_basic_int(bas, lend, &i);
                    zx_out(&cpu, 0xFEu, (u8)(b & 7u));
                } else if (tk == 0xDFu) { /* OUT <port>, <val> */
                    u16 p = parse_basic_int(bas, lend, &i);
                    while (i < lend && bas[i] != ',') i++;
                    if (i < lend && bas[i] == ',') i++;
                    u16 v = parse_basic_int(bas, lend, &i);
                    zx_out(&cpu, p, (u8)v);
                } else if (tk == 0xF4u) { /* POKE <addr>, <val> */
                    u16 a = parse_basic_int(bas, lend, &i);
                    while (i < lend && bas[i] != ',') i++;
                    if (i < lend && bas[i] == ',') i++;
                    u16 v = parse_basic_int(bas, lend, &i);
                    ram_poke_fast(a, (u8)v);
                } else if (tk == 0xEFu) { /* LOAD "" [SCREEN$ | CODE [addr]] */
                    int is_scr = 0, has_code = 0;
                    u16 explicit_addr = 0;
                    while (i < lend && bas[i] != ':' && bas[i] != 0x0Du) {
                        if (bas[i] == 0x0Eu) { i += 6; continue; }
                        if (bas[i] == 0xAAu) { is_scr = 1; i++; break; }
                        if (bas[i] == 0xAFu) {
                            has_code = 1;
                            i++;
                            while (i < lend && bas[i] == ' ') i++;
                            if (i < lend && bas[i] != ':' && bas[i] != 0x0Du && bas[i] != ',')
                                explicit_addr = parse_basic_int(bas, lend, &i);
                            break;
                        }
                        i++;
                    }
                    /* Consume next header + data pair (or headerless data block) */
                    if (block_at < blocks) {
                        u16 load_to = is_scr ? 0x4000u : explicit_addr;
                        u32 d_idx = (u32)block_at;
                        if (M->block_n[d_idx] >= 19 && M->block[d_idx][0] == 0x00u && d_idx + 1u < (u32)blocks) {
                            u16 hdr_start = (u16)(M->block[d_idx][14] | ((u16)M->block[d_idx][15] << 8));
                            if (!load_to) load_to = hdr_start;
                            d_idx++;
                            block_at = (int)(d_idx + 1u);
                        } else {
                            block_at = (int)(d_idx + 1u);
                        }
                        if (d_idx < (u32)blocks && M->block_n[d_idx] >= 2) {
                            const u8 *d = M->block[d_idx] + 1;
                            u32 dn = M->block_n[d_idx] - 2u;
                            if (!load_to) load_to = 0x8000u;
                            for (u32 k = 0; k < dn; k++)
                                ram_poke_fast((u16)(load_to + k), d[k]);
                            if (!is_scr && (has_code || load_to != 0x4000u))
                                last_code_addr = load_to;
                        }
                    }
                } else if (tk == 0xC0u) { /* USR <addr> */
                    u16 u = parse_basic_int(bas, lend, &i);
                    if (u >= 0x4000u) {
                        usr_target = u;
                        break;
                    }
                }
            }
            pos = lend;
        }
    }

    /* If any standard Header+Code pairs remain and we didn't find USR yet, load them too */
    while (!usr_target && block_at + 1 < blocks && M->block_n[block_at] >= 19 && M->block[block_at][0] == 0x00u) {
        u8 btype = M->block[block_at][1];
        u16 start = (u16)(M->block[block_at][14] | ((u16)M->block[block_at][15] << 8));
        const u8 *d = M->block[block_at + 1] + 1;
        u32 dn = M->block_n[block_at + 1] >= 2 ? M->block_n[block_at + 1] - 2u : 0;
        block_at += 2;
        if (btype == 3) {
            for (u32 k = 0; k < dn; k++)
                ram_poke_fast((u16)(start + k), d[k]);
            if (start != 0x4000u)
                last_code_addr = start;
        }
    }

    u16 entry = usr_target ? usr_target : (last_code_addr ? last_code_addr : 0);
    if (entry) {
        cpu.sp.w = sp_target;
        cpu.pc.w = entry;
        cpu.im = 1;
        cpu.iff1 = cpu.iff2 = 1;
        cpu.trap = (block_at < blocks) ? LD_BYTES : -1;
    }
}

static void hle_boot_trd(void)
{
    /* Find 'boot    B' first, else the first 'B' file, else the first 'C' file */
    int boot_idx = -1, first_b = -1, first_c = -1;
    for (int idx = 0; idx < 128; idx++) {
        const u8 *e = M->trd + idx * 16;
        if (e[0] == 0x00u) break;
        if (e[0] == 0x01u) continue;
        if (e[8] == 'B') {
            if (first_b < 0) first_b = idx;
            int is_boot = 1;
            static const char bname[8] = {'b','o','o','t',' ',' ',' ',' '};
            for (int k = 0; k < 8; k++) {
                char c = (char)e[k];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                if (c != bname[k]) { is_boot = 0; break; }
            }
            if (is_boot) { boot_idx = idx; break; }
        } else if (e[8] == 'C' && first_c < 0) {
            first_c = idx;
        }
    }
    int pick = boot_idx >= 0 ? boot_idx : (first_b >= 0 ? first_b : first_c);
    if (pick < 0)
        return;

    const u8 *ent = M->trd + pick * 16;
    u16 start = (u16)(ent[9] | ((u16)ent[10] << 8));
    u16 blen  = (u16)(ent[11] | ((u16)ent[12] << 8));
    u8  slen  = ent[13];
    u8  sec   = ent[14] & 15u;
    u8  trk   = ent[15];
    u32 total = (u32)slen * 256u;
    u32 off   = ((u32)trk * 16u + sec) * 256u;
    u32 end_sec = (u32)trk * 16u + sec + slen;
    ram_poke_fast(0x5CF4u, (u8)(end_sec & 15u));
    ram_poke_fast(0x5CF5u, (u8)(end_sec >> 4));

    if (ent[8] == 'C') {
        u16 dst = start >= 0x4000u ? start : 0x8000u;
        u32 n = blen ? blen : total;
        for (u32 i = 0; i < n && off + i < TRD_MAX; i++)
            ram_poke_fast((u16)(dst + i), M->trd[off + i]);
        cpu.sp.w = 0xFF40u;
        cpu.pc.w = dst;
        cpu.im = 1;
        cpu.iff1 = cpu.iff2 = 1;
        return;
    }

    /* BASIC 'B' file: load into $5CCB (PROG) */
    ram_poke_fast(0x5C53u, 0xCBu);
    ram_poke_fast(0x5C54u, 0x5Cu);
    for (u32 i = 0; i < total && 0x5CCBu + i < 0xFF00u && off + i < TRD_MAX; i++)
        ram_poke_fast((u16)(0x5CCBu + i), M->trd[off + i]);

    const u8 *bas = M->trd + off;
    u32 prog_len = start ? start : (blen ? blen : total);
    if (prog_len > total) prog_len = total;
    u16 sp_target = 0xFF40u;
    u16 usr_target = 0;
    u16 last_code = 0;

    int chain_hops = 0;
    u32 pos = 0;
    while (pos + 4 <= prog_len && !usr_target) {
        u16 llen = (u16)(bas[pos + 2] | ((u16)bas[pos + 3] << 8));
        pos += 4;
        u32 lend = pos + llen;
        if (lend > prog_len) lend = prog_len;
        u32 i = pos;
        int chained = 0;
        while (i < lend) {
            u8 tk = bas[i++];
            if (tk == 0xEAu) break;     /* REM */
            if (tk == 0x0Eu) { i += 5; continue; }
            if (tk == 0xFDu) {
                u16 a = parse_basic_int(bas, lend, &i);
                if (a >= 0x5D00u) sp_target = a;
            } else if (tk == 0xDFu) {
                u16 p = parse_basic_int(bas, lend, &i);
                while (i < lend && bas[i] != ',') i++;
                if (i < lend && bas[i] == ',') i++;
                u16 v = parse_basic_int(bas, lend, &i);
                zx_out(&cpu, p, (u8)v);
            } else if (tk == 0xF4u) {
                u16 a = parse_basic_int(bas, lend, &i);
                while (i < lend && bas[i] != ',') i++;
                if (i < lend && bas[i] == ',') i++;
                u16 v = parse_basic_int(bas, lend, &i);
                ram_poke_fast(a, (u8)v);
            } else if (tk == 0xC0u) {   /* USR */
                u16 u = parse_basic_int(bas, lend, &i);
                if (u == 15619u || u == 15616u) {
                    /* TR-DOS command in ": REM : LOAD/RUN \"name\" [CODE [addr]]" */
                    while (i < lend && bas[i] != 0xEAu) i++;
                    if (i < lend && bas[i] == 0xEAu) i++;
                    while (i < lend && (bas[i] == ':' || bas[i] == ' ')) i++;
                    if (i < lend && (bas[i] == 0xEFu || bas[i] == 0xF7u)) { /* LOAD or RUN */
                        u8 cmd_tk = bas[i++];
                        while (i < lend && bas[i] != '"') i++;
                        if (i < lend && bas[i] == '"') {
                            i++;
                            char fn[8] = {' ',' ',' ',' ',' ',' ',' ',' '};
                            int fk = 0;
                            while (i < lend && bas[i] != '"' && fk < 8)
                                fn[fk++] = (char)bas[i++];
                            while (i < lend && bas[i] != '"') i++;
                            if (i < lend && bas[i] == '"') i++;
                            int is_scr = 0, has_code_kw = 0;
                            u16 exp_addr = 0;
                            while (i < lend && bas[i] != ':' && bas[i] != 0x0Du) {
                                if (bas[i] == 0xAAu) { is_scr = 1; i++; break; }
                                if (bas[i] == 0xAFu) {
                                    has_code_kw = 1;
                                    i++;
                                    exp_addr = parse_basic_int(bas, lend, &i);
                                    break;
                                }
                                i++;
                            }
                            /* Look up fn in TR-DOS catalog ('C' first, then 'B' if RUN/LOAD BASIC) */
                            int matched_c = 0;
                            for (int ci = 0; ci < 128; ci++) {
                                const u8 *ce = M->trd + ci * 16;
                                if (ce[0] == 0x00u) break;
                                if (ce[0] == 0x01u || ce[8] != 'C') continue;
                                int m = 1;
                                for (int k = 0; k < 8; k++)
                                    if (ce[k] != (u8)fn[k]) { m = 0; break; }
                                if (m) {
                                    matched_c = 1;
                                    u16 c_st = is_scr ? 0x4000u : (exp_addr ? exp_addr : (u16)(ce[9] | (ce[10] << 8)));
                                    u16 c_ln = (u16)(ce[11] | (ce[12] << 8));
                                    u32 c_tot = c_ln ? c_ln : (u32)ce[13] * 256u;
                                    u32 c_off = ((u32)ce[15] * 16u + (ce[14] & 15u)) * 256u;
                                    for (u32 b = 0; b < c_tot && c_off + b < TRD_MAX; b++)
                                        ram_poke_fast((u16)(c_st + b), M->trd[c_off + b]);
                                    u32 es = (u32)ce[15] * 16u + (ce[14] & 15u) + ce[13];
                                    ram_poke_fast(0x5CF4u, (u8)(es & 15u));
                                    ram_poke_fast(0x5CF5u, (u8)(es >> 4));
                                    if (!is_scr && c_st != 0x4000u)
                                        last_code = c_st;
                                    if (cmd_tk == 0xF7u)
                                        usr_target = c_st;
                                    break;
                                }
                            }
                            if (!matched_c && !has_code_kw && !is_scr && chain_hops < 3) {
                                for (int bi = 0; bi < 128; bi++) {
                                    const u8 *be = M->trd + bi * 16;
                                    if (be[0] == 0x00u) break;
                                    if (be[0] == 0x01u || be[8] != 'B') continue;
                                    int m = 1;
                                    for (int k = 0; k < 8; k++)
                                        if (be[k] != (u8)fn[k]) { m = 0; break; }
                                    if (m) {
                                        u32 b_tot = (u32)be[13] * 256u;
                                        u32 b_off = ((u32)be[15] * 16u + (be[14] & 15u)) * 256u;
                                        u16 b_st = (u16)(be[9] | (be[10] << 8));
                                        u16 b_ln = (u16)(be[11] | (be[12] << 8));
                                        for (u32 b = 0; b < b_tot && 0x5CCBu + b < 0xFF00u && b_off + b < TRD_MAX; b++)
                                            ram_poke_fast((u16)(0x5CCBu + b), M->trd[b_off + b]);
                                        bas = M->trd + b_off;
                                        total = b_tot;
                                        off = b_off;
                                        prog_len = b_st ? b_st : (b_ln ? b_ln : b_tot);
                                        if (prog_len > b_tot) prog_len = b_tot;
                                        pos = 0;
                                        chain_hops++;
                                        chained = 1;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else if (u >= 0x4000u) {
                    usr_target = u;
                    break;
                }
            }
            if (chained) break;
        }
        if (!chained)
            pos = lend;
    }

    /* Fallback: if boot.B had machine code right after BASIC without explicit USR parsed, scan for C0 0E float */
    if (!usr_target && !last_code) {
        for (u32 i = 0; i + 6 < total && off + i + 6 < TRD_MAX; i++) {
            if (bas[i] == 0xC0u) {
                u32 p = i + 1u;
                u16 u = parse_basic_int(bas, total, &p);
                if (u >= 0x4000u && u != 15619u && u != 15616u) {
                    usr_target = u;
                    break;
                }
            }
        }
    }
    /* Or load first 'C' file on the disk if boot.B loaded a menu/game we missed */
    if (!usr_target && !last_code && first_c >= 0) {
        const u8 *ce = M->trd + first_c * 16;
        u16 c_st = (u16)(ce[9] | (ce[10] << 8));
        u16 c_ln = (u16)(ce[11] | (ce[12] << 8));
        u32 c_tot = c_ln ? c_ln : (u32)ce[13] * 256u;
        u32 c_off = ((u32)ce[15] * 16u + (ce[14] & 15u)) * 256u;
        if (c_st >= 0x4000u) {
            for (u32 b = 0; b < c_tot && c_off + b < TRD_MAX; b++)
                ram_poke_fast((u16)(c_st + b), M->trd[c_off + b]);
            last_code = c_st;
        }
    }

    u16 entry = usr_target ? usr_target : last_code;
    if (entry) {
        cpu.sp.w = sp_target;
        cpu.pc.w = entry;
        cpu.im = 1;
        cpu.iff1 = cpu.iff2 = 1;
    }
}

static void build_clean_roms(void)
{
    u8 *r0 = M->rom_builtin[0];
    u8 *r1 = M->rom_builtin[1];
    u8 *rt = M->rom_trdos_buf;
    for (u32 i = 0; i < 0x4000u; i++) {
        r0[i] = 0xC9u;
        r1[i] = 0xC9u;
        rt[i] = 0xC9u;
    }

    /* 8x8 ASCII font at $3D00..$3FFF in both ROM 0 and ROM 1 */
    for (u32 ch = 0; ch < 96u; ch++)
        for (u32 row = 0; row < 8u; row++)
            r0[0x3D00u + ch * 8u + row] = r1[0x3D00u + ch * 8u + row] = zx_font96[ch][row];

    /* $0000: DI; XOR A; LD SP,$FF40; IM 1; JP $0100 (matches 0xF3, 0xAF signature) */
    static const u8 boot_stub[] = {
        0xF3, 0xAF,                     /* DI; XOR A */
        0x31, 0x40, 0xFF,               /* LD SP, $FF40 */
        0xED, 0x56,                     /* IM 1 */
        0xC3, 0x00, 0x01                /* JP $0100 */
    };
    for (u32 i = 0; i < sizeof(boot_stub); i++)
        r0[i] = r1[i] = boot_stub[i];

    /* $0038: IM 1 interrupt routine (increments 24-bit FRAMES at $5C78, updates LAST_K via HLE $E5, EI, RET) */
    static const u8 im1_isr[] = {
        0xF5, 0xE5,                     /* PUSH AF; PUSH HL */
        0x2A, 0x78, 0x5C,               /* LD HL, ($5C78) */
        0x23,                           /* INC HL */
        0x22, 0x78, 0x5C,               /* LD ($5C78), HL */
        0x7C, 0xB5, 0x20, 0x06,         /* LD A,H; OR L; JR NZ, +6 */
        0x21, 0x7A, 0x5C, 0x34,         /* LD HL,$5C7A; INC (HL) */
        0xD3, 0xE5,                     /* OUT ($E5), A  (HLE keyboard scan -> LAST_K / FLAGS) */
        0xE1, 0xF1,                     /* POP HL; POP AF */
        0xFB, 0xC9                      /* EI; RET */
    };
    for (u32 i = 0; i < sizeof(im1_isr); i++)
        r0[0x0038u + i] = r1[0x0038u + i] = im1_isr[i];

    /* $0100: System init + HLE tape/disk boot trigger + idle loop */
    static const u8 main_loop[] = {
        0xFD, 0x21, 0x3A, 0x5C,         /* LD IY, $5C3A (ERR_NR) */
        0x21, 0x00, 0x3C,               /* LD HL, $3C00 (CHARS) */
        0x22, 0x36, 0x5C,               /* LD ($5C36), HL */
        0x3E, 0x38,                     /* LD A, $38 (white paper, black ink) */
        0x32, 0x8D, 0x5C,               /* LD ($5C8D), A (ATTR_P) */
        0x32, 0x48, 0x5C,               /* LD ($5C48), A (BORDCR) */
        0xCD, 0x6B, 0x0D,               /* CALL $0D6B (CLS) */
        0xFB,                           /* EI */
        0x76,                           /* HALT */
        0xD3, 0xE4,                     /* OUT ($E4), A (HLE tape/TRD boot if queued) */
        0x18, 0xFB                      /* JR -5 (HALT loop) */
    };
    for (u32 i = 0; i < sizeof(main_loop); i++)
        r0[0x0100u + i] = r1[0x0100u + i] = main_loop[i];

    /* $03B5: ROM BEEPER (HL = pitch loop count, DE = duration cycles) */
    static const u8 beeper_sub[] = {
        0xF3, 0x7D, 0xD5, 0xAF,         /* DI; LD A,L; PUSH DE; XOR A */
        /* loop: */
        0xEE, 0x10, 0xD3, 0xFE,         /* XOR $10; OUT ($FE),A */
        0x45, 0x10, 0xFE,               /* LD B,L; DJNZ . */
        0x1B, 0x7A, 0xB3, 0x20, 0xF5,   /* DEC DE; LD A,D; OR E; JR NZ, loop */
        0xD1, 0xFB, 0xC9                /* POP DE; EI; RET */
    };
    for (u32 i = 0; i < sizeof(beeper_sub); i++)
        r0[0x03B5u + i] = r1[0x03B5u + i] = beeper_sub[i];

    /* $053F: SA_LD_RET -> EI; RET; $0556: LD_BYTES -> SCF; RET (trapped when tape blocks remain) */
    r0[SA_LD_RET] = r1[SA_LD_RET] = 0xFBu;
    r0[SA_LD_RET + 1] = r1[SA_LD_RET + 1] = 0xC9u;
    r0[LD_BYTES] = r1[LD_BYTES] = 0x37u;
    r0[LD_BYTES + 1] = r1[LD_BYTES + 1] = 0xC9u;

    /* $0D6B: CLS ($4000..$57FF = 0, $5800..$5AFF = ($5C8D)) */
    static const u8 cls_sub[] = {
        0x21, 0x00, 0x40, 0x11, 0x01, 0x40, 0x01, 0xFF, 0x17, 0x36, 0x00, 0xED, 0xB0,
        0x3A, 0x8D, 0x5C, 0x21, 0x00, 0x58, 0x11, 0x01, 0x58, 0x01, 0xFF, 0x02, 0x77, 0xED, 0xB0,
        0xC9
    };
    for (u32 i = 0; i < sizeof(cls_sub); i++)
        r0[0x0D6Bu + i] = r1[0x0D6Bu + i] = cls_sub[i];

    /* TR-DOS built-in ROM: $3D00 & $3D13 -> OUT ($E7), A; JP $3FF0 (at $3FF0 -> RET to RAM unpages TR-DOS!) */
    rt[0x0038u] = 0xFBu; rt[0x0039u] = 0xC9u;
    rt[0x3D00u] = 0xC9u;
    rt[0x3D13u] = 0xD3u; rt[0x3D14u] = 0xE7u; rt[0x3D15u] = 0xC9u;
    rt[0x3D2Fu] = 0xC9u;                /* Common TR-DOS NOP gadget used to page in BetaDisk */
    /* Standard TR-DOS ROM tail gadgets used by direct-WD1793 loaders: */
    rt[0x3FF8u] = 0xEDu; rt[0x3FF9u] = 0x79u; rt[0x3FFAu] = 0xC9u;  /* OUT (C),A; RET */
    rt[0x3FFBu] = 0xEDu; rt[0x3FFCu] = 0x78u; rt[0x3FFDu] = 0xC9u;  /* IN A,(C); RET */
    rt[0x3FFEu] = 0xE9u;                                            /* JP (HL) */
}

static void hle_scan_kbd_sysvars(void)
{
    static const char map[8][5] = {
        {0, 'z', 'x', 'c', 'v'},
        {'a', 's', 'd', 'f', 'g'},
        {'q', 'w', 'e', 'r', 't'},
        {'1', '2', '3', '4', '5'},
        {'0', '9', '8', '7', '6'},
        {'p', 'o', 'i', 'u', 'y'},
        {'\r','l', 'k', 'j', 'h'},
        {' ', 0,   'm', 'n', 'b'}
    };
    for (int r = 0; r < 8; r++) {
        for (int b = 0; b < 5; b++) {
            if ((keys[r] & (1u << b)) && map[r][b]) {
                ram_poke_fast(0x5C08u, (u8)map[r][b]);
                ram_poke_fast(0x5C3Bu, (u8)(ram_peek_fast(0x5C3Bu) | 0x20u));
                return;
            }
        }
    }
}

/* ---- ULA & I/O Ports ---- */
static u8 floating_bus(void)
{
    s32 t = cpu.cycles - 1 - paper_t;
    if (t < 0 || t >= 192 * line_t)
        return 0xFF;
    int y = t / line_t, x = t % line_t;
    if (x >= 128 || (x & 7) >= 4)
        return 0xFF;
    const u8 *scr = M->ram[(port_7ffd & 0x08u) ? 7 : 5];
    int col = (x >> 3) * 2 + ((x >> 1) & 1);
    if (x & 1)
        return scr[0x1800 + (y >> 3) * 32 + col];
    return scr[((y & 0xC0) << 5) | ((y & 7) << 8) | ((y & 0x38) << 2) | col];
}

static u8 zx_in(struct z80 *c, u16 port)
{
    (void)c;
    /* BetaDisk WD1793 ports when TR-DOS ROM is active */
    if (trdos_active && (port & 0x03u) == 0x03u) {
        u8 lo = (u8)port;
        if (lo == 0x1Fu || lo == 0x3Fu || lo == 0x5Fu || lo == 0x7Fu || lo == 0xFFu)
            return wd_read(lo);
    }
    /* ULA keyboard + EAR */
    if (!(port & 1u)) {
        u8 v = (u8)(0xBFu | ((ear_out & 0x10u) << 2));
        for (int r = 0; r < 8; r++)
            if (!(port & (0x100u << r)))
                v &= (u8)~keys[r];
        return v;
    }
    /* AY-3-8912 register read: 0xFFFD -> (port & 0xC002) == 0xC000 */
    if ((port & 0xC002u) == 0xC000u)
        return ay.reg_sel < 16u ? ay.reg[ay.reg_sel] : 0xFFu;
    /* Kempston joystick: port 0x1F (A5..A7 == 0) */
    if (!(port & 0xE0u))
        return kempston;
    return floating_bus();
}

static void zx_out(struct z80 *c, u16 port, u8 v)
{
    /* Internal HLE traps when running built-in ROMs */
    if (using_builtin_rom && c->pc.w < 0x0200u) {
        if ((u8)port == 0xE5u) {
            hle_scan_kbd_sysvars();
            return;
        }
        if ((u8)port == 0xE4u) {
            if (builtin_tape_boot) {
                builtin_tape_boot = 0;
                hle_boot_tape();
            } else if (builtin_trd_boot) {
                builtin_trd_boot = 0;
                hle_boot_trd();
            }
            return;
        }
    }
    if (trdos_active && !has_ext_trdos && (u8)port == 0xE7u && c->pc.w < 0x4000u) {
        trdos_hle_3d13();
        return;
    }
    /* BetaDisk WD1793 ports when TR-DOS ROM is active */
    if (trdos_active && (port & 0x03u) == 0x03u) {
        u8 lo = (u8)port;
        if (lo == 0x1Fu || lo == 0x3Fu || lo == 0x5Fu || lo == 0x7Fu || lo == 0xFFu) {
            wd_write(lo, v);
            return;
        }
    }
    /* ULA border + beeper */
    if (!(port & 1u)) {
        if ((ear_out ^ v) & 0x18u)
            audio_catch_up();
        ear_out = v;
        if ((v & 7u) != border) {
            border = v & 7u;
            if (changes < CHANGES) {
                M->change_t[changes] = c->cycles;
                M->change_c[changes++] = border;
            } else {
                M->change_c[CHANGES - 1] = border;
            }
        }
    }
    /* Spectrum 128K paging register 0x7FFD: A15 == 0 and A1 == 0 */
    if ((port & 0x8002u) == 0u && !(port_7ffd & 0x20u)) {
        port_7ffd = v;
        is_128k = 1;
        rebuild_map();
    }
    /* AY-3-8912 register select (0xFFFD: A15=1, A14=1, A1=0) and data write (0xBFFD: A15=1, A14=0, A1=0) */
    if ((port & 0xC002u) == 0xC000u)
        ay.reg_sel = v & 0x0Fu;
    else if ((port & 0xC002u) == 0x8000u)
        ay_write_reg(ay.reg_sel, v);
}

/* ---- Video Rendering ---- */
static void paper_line(int y)
{
    u16 *outp = pic + (24 + y) * ZX_W + 32;
    const u8 *scr = M->ram[(port_7ffd & 0x08u) ? 7 : 5];
    const u8 *bits = scr + (((y & 0xC0) << 5) | ((y & 7) << 8) | ((y & 0x38) << 2));
    const u8 *attr = scr + 0x1800 + (y >> 3) * 32;
    u8 flash = (frames & 16) ? 0xFF : 0;
    for (int col = 0; col < 32; col++, outp += 8) {
        u8 a = attr[col], b = bits[col];
        u16 ink = colour[(a & 7) | ((a >> 3) & 8)], paper = colour[((a >> 3) & 7) | ((a >> 3) & 8)];
        if (a & 0x80)
            b ^= flash;
        for (int i = 0; i < 8; i++, b <<= 1)
            outp[i] = (b & 0x80) ? ink : paper;
    }
}

static void border_lines(void)
{
    int at = 0;
    u16 now = colour[border_was];
    int p_first = top_line + 24;
    for (int y = 0; y < ZX_H; y++) {
        int line = top_line + y;
        s32 t0 = line * line_t - 16;
        u16 *outp = pic + y * ZX_W;
        int paper = line >= p_first && line < p_first + 192;
        for (int x = 0; x < ZX_W; x += 2) {
            if (paper && x == 32)
                x = 288;
            s32 t = t0 + (x >> 1);
            while (at < changes && M->change_t[at] <= t)
                now = colour[M->change_c[at++]];
            outp[x] = outp[x + 1] = now;
        }
    }
}

/* ---- Tape Trap ---- */
static void tape_block(void)
{
    const u8 *b = M->block[block_at];
    u32 n = M->block_n[block_at], len = cpu.de.w, k = 0;
    int ok = 0;
    block_at++;
    if (n >= 2 && b[0] == cpu.af.b.h) {
        u8 sum = b[0];
        int load = cpu.af.b.l & Z80_FC;
        for (; k < len && k + 2 < n; k++) {
            u8 v = b[1 + k];
            u16 a = (u16)(cpu.ix.w + k);
            sum ^= v;
            if (load && a >= 0x4000u)
                ram_poke_fast(a, v);
        }
        ok = k == len && (sum ^ b[1 + k]) == 0;
        cpu.ix.w = (u16)(cpu.ix.w + k);
        cpu.de.w = (u16)(cpu.de.w - k);
    }
    cpu.af.b.l = (u8)(ok ? cpu.af.b.l | Z80_FC : cpu.af.b.l & ~Z80_FC);
    cpu.pc.w = SA_LD_RET;
    if (block_at >= blocks)
        cpu.trap = -1;
}

static void run_to(s32 t)
{
    while (z80_run(&cpu, t))
        tape_block();
}

void zx_frame(u8 pad, const u8 matrix[8], u16 *picture)
{
    pic = picture;
    audio_count = 0;
    audio_last_cyc = cpu.cycles;

    if (auto_load) {
        u32 count = (u32)(M->ram[5][0x1C78] | ((u32)M->ram[5][0x1C79] << 8));
        if (count >= 20 && count <= frames) {
            zx_type("j\"\"\n");
            auto_load = 0;
        }
    }
    u8 now[8] = {0};
    if (matrix)
        for (int r = 0; r < 8; r++)
            now[r] = matrix[r];
    typed(now);
    if (pad & ZX_START)
        now[6] |= 0x01;
    if (pad & ZX_SELECT)
        now[7] |= 0x01;
    for (int r = 0; r < 8; r++)
        keys[r] = now[r] & 0x1F;
    kempston = (u8)(((pad & ZX_RIGHT) ? 1 : 0) | ((pad & ZX_LEFT) ? 2 : 0) | ((pad & ZX_DOWN) ? 4 : 0) |
                    ((pad & ZX_UP) ? 8 : 0) | ((pad & (ZX_A | ZX_B)) ? 0x10 : 0));

    border_was = border;
    changes = 0;
    cpu.irq = 1;
    run_to(INT_T);
    cpu.irq = 0;
    for (int y = 0; y < 192; y++) {
        run_to(paper_t + y * line_t);
        if (pic)
            paper_line(y);
    }
    run_to(frame_t);
    audio_catch_up();
    if (pic)
        border_lines();
    cpu.cycles -= frame_t;
    cycles_hi += (u32)frame_t;
    frames++;
}

static void setup_timing(int m128)
{
    is_128k = (u8)(m128 ? 1 : 0);
    if (is_128k) {
        line_t = LINE_T_128;
        lines_n = LINES_128;
        frame_t = FRAME_T_128;
        paper_t = PAPER_T_128;
        top_line = 39;                  /* 63 - 24 */
    } else {
        line_t = LINE_T_48;
        lines_n = LINES_48;
        frame_t = FRAME_T_48;
        paper_t = PAPER_T_48;
        top_line = 40;                  /* 64 - 24 */
    }
    static const u8 delay[8] = {6, 5, 4, 3, 2, 1, 0, 0};
    for (int t = 0; t < frame_t + 256; t++) {
        int d = t - (paper_t - 1);
        M->cont[t] = (d >= 0 && d < 192 * line_t && d % line_t < 128) ? delay[d & 7] : 0;
    }
}

void zx_set_extra_roms(const u8 *rom128_32k, u32 rom128_size, const u8 *trdos_16k, u32 trdos_size)
{
    has_ext_128 = 0;
    has_ext_trdos = 0;
    if (rom128_32k && rom128_size == 0x8000u) {
        for (u32 i = 0; i < 0x4000u; i++) {
            M->rom_128_ext[0][i] = rom128_32k[i];
            M->rom_128_ext[1][i] = rom128_32k[0x4000u + i];
        }
        has_ext_128 = 1;
    }
    if (trdos_16k && trdos_size == 0x4000u) {
        for (u32 i = 0; i < 0x4000u; i++)
            M->rom_trdos_ext[i] = trdos_16k[i];
        has_ext_trdos = 1;
    }
}

void zx_reset(void)
{
    setup_timing(has_ext_128 || has_trd);
    for (int i = 0; i < 16; i++)
        colour[i] = (u16)((zx_rgb[i][0] >> 3) | ((zx_rgb[i][1] >> 3) << 5) | ((zx_rgb[i][2] >> 3) << 10));

    z80_init(&cpu);
    cpu.read = zx_mem_read;
    cpu.write = zx_mem_write;
    cpu.in = zx_in;
    cpu.out = zx_out;
    cpu.cont_lo = 0x4000;
    cpu.cont_n = 0x4000;
    cpu.cont = M->cont;

    for (int b = 0; b < 8; b++)
        for (int i = 0; i < 0x4000; i++)
            M->ram[b][i] = 0;

    /* Default to ROM 1 (48K BASIC) with 128K paging unlocked so both 48K and 128K tapes/disks run! */
    port_7ffd = 0x10u;
    trdos_active = 0;
    rebuild_map();

    for (u32 i = 0; i < sizeof(ay); i++)
        ((u8 *)&ay)[i] = 0;
    ay.reg[7] = 0x3Fu;
    ay.lfsr = 1u;

    for (u32 i = 0; i < sizeof(fdc); i++)
        ((u8 *)&fdc)[i] = 0;
    fdc.sector = 1;
    fdc.status = 0x04u;

    border = 7;
    border_was = 7;
    changes = 0;
    ear_out = 0;
    frames = 0;
    cycles_hi = 0;
    q_head = q_tail = q_frame = 0;
    block_at = 0;
    beep_dc = 0;

    if (blocks) {
        if (using_builtin_rom) {
            cpu.trap = -1;
            auto_load = 0;
            builtin_tape_boot = 1;
        } else {
            cpu.trap = LD_BYTES;
            auto_load = 1;
            builtin_tape_boot = 0;
        }
    } else {
        cpu.trap = -1;
        auto_load = 0;
        builtin_tape_boot = 0;
    }
    builtin_trd_boot = has_trd ? 1 : 0;
    if (has_trd && !using_builtin_rom && has_ext_trdos) {
        /* With real 48/128 ROM + real trdos.rom: boot into TR-DOS or type RANDOMIZE USR 15616 */
        builtin_trd_boot = 0;
        trdos_active = 1;
        rebuild_map();
        zx_type("r\n");                 /* RUN on TR-DOS prompt */
    } else if (has_trd && !using_builtin_rom && !has_ext_trdos) {
        /* Real 48/128 ROM without trdos.rom: boot TRD directly via HLE after reset */
        builtin_trd_boot = 0;
    }
}

/* ---- File Loaders (.tap, .tzx, .z80, .sna, .trd, .scl) ---- */
static int ends_with(const char *name, const char *ext)
{
    int n = 0, e = 0;
    while (name && name[n])
        n++;
    while (ext[e])
        e++;
    if (n < e)
        return 0;
    for (int i = 0; i < e; i++) {
        char c = name[n - e + i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + 32);
        if (c != ext[i])
            return 0;
    }
    return 1;
}

static char *put(char *p, const char *s)
{
    while (*s && p < info + sizeof(info) - 1)
        *p++ = *s++;
    *p = 0;
    return p;
}

static char *put_number(char *p, u32 v)
{
    char d[12];
    int n = 0;
    do
        d[n++] = (char)('0' + v % 10);
    while (v /= 10);
    while (n && p < info + sizeof(info) - 1)
        *p++ = d[--n];
    *p = 0;
    return p;
}

static void add_block(const u8 *b, u32 n)
{
    if (blocks < BLOCKS) {
        M->block[blocks] = b;
        M->block_n[blocks++] = n;
    }
}

static const char *load_tap(const u8 *f, u32 size)
{
    for (u32 at = 0; at + 2 <= size;) {
        u32 n = (u32)(f[at] | (f[at + 1] << 8));
        if (at + 2 + n > size)
            return "a .tap file whose last block is cut short";
        add_block(f + at + 2, n);
        at += 2 + n;
    }
    return blocks ? 0 : "an empty .tap file";
}

#define W16(p) ((u32)((p)[0] | ((p)[1] << 8)))
#define W24(p) ((u32)((p)[0] | ((p)[1] << 8) | ((p)[2] << 16)))
#define W32(p) ((u32)((p)[0] | ((p)[1] << 8) | ((p)[2] << 16) | ((u32)(p)[3] << 24)))

static const char *load_tzx(const u8 *f, u32 size)
{
    static const char sig[8] = {'Z', 'X', 'T', 'a', 'p', 'e', '!', 0x1A};
    for (int i = 0; i < 8; i++)
        if (size < 10 || f[i] != (u8)sig[i])
            return "not a .tzx file (no ZXTape! signature)";
    u32 at = 10;
    while (at < size) {
        u8 id = f[at++], tail[24] = {0};
        const u8 *p = f + at;
        u32 skip;
        if (size - at < 20) {
            for (u32 i = 0; at + i < size; i++)
                tail[i] = f[at + i];
            p = tail;
        }
        switch (id) {
        case 0x10: skip = 4 + W16(p + 2); if (at + skip <= size) add_block(f + at + 4, W16(p + 2)); break;
        case 0x11: skip = 18 + W24(p + 15); if (at + skip <= size) add_block(f + at + 18, W24(p + 15)); break;
        case 0x14: skip = 10 + W24(p + 7); if (at + skip <= size) add_block(f + at + 10, W24(p + 7)); break;
        case 0x12: skip = 4; break;
        case 0x13: skip = 1 + 2 * (u32)p[0]; break;
        case 0x15: skip = 8 + W24(p + 5); break;
        case 0x18: case 0x19: skip = 4 + W32(p); break;
        case 0x20: case 0x23: case 0x24: skip = 2; break;
        case 0x21: case 0x30: skip = 1 + (u32)p[0]; break;
        case 0x22: case 0x25: case 0x27: skip = 0; break;
        case 0x26: skip = 2 + 2 * W16(p); break;
        case 0x28: case 0x32: skip = 2 + W16(p); break;
        case 0x2A: skip = 4; break;
        case 0x2B: skip = 5; break;
        case 0x31: skip = 2 + (u32)p[1]; break;
        case 0x33: skip = 1 + 3 * (u32)p[0]; break;
        case 0x35: skip = 20 + W32(p + 16); break;
        case 0x5A: skip = 9; break;
        default:
            if (blocks)
                return 0;
            return "a .tzx block this player does not know (it reads the data blocks: 0x10, 0x11, 0x14)";
        }
        if (skip > size - at)
            break;
        at += skip;
    }
    return blocks ? 0 : "a .tzx file with no data blocks";
}

static u32 unpack_z80_page(const u8 *src, u32 n, u8 *to, u32 room)
{
    u32 i = 0, o = 0;
    while (i < n && o < room) {
        if (i + 3 < n && src[i] == 0xED && src[i + 1] == 0xED) {
            for (u32 k = 0; k < src[i + 2] && o < room; k++)
                to[o++] = src[i + 3];
            i += 4;
        } else {
            to[o++] = src[i++];
        }
    }
    return i;
}

static const char *snapshot_z80(const u8 *h, u32 size)
{
    if (size < 30)
        return "a .z80 file shorter than its header";
    u8 flags = h[12] == 0xFF ? 1 : h[12];
    u16 pc = (u16)(h[6] | (h[7] << 8));
    int version = 1;
    int snap_128 = 0;

    if (!pc) {
        u32 extra = W16(h + 30);
        version = extra == 23 ? 2 : 3;
        if (size < 32 + extra || extra < 23)
            return "a .z80 file shorter than its header";
        u8 mode = h[34];
        /* v2: 0/1 = 48K, 3/4 = 128K; v3: 0/1/3 = 48K, 4/5/6 = 128K; 7/8/9/12/13 = +3/Pentagon 128K */
        if (version == 2)
            snap_128 = (mode >= 3);
        else
            snap_128 = (mode >= 4);

        setup_timing(snap_128);
        if (snap_128) {
            port_7ffd = h[35];
        } else {
            port_7ffd = 0x30u;          /* 48K locked */
        }
        if (extra >= 23 && 39 + 16 <= 32 + extra) {
            ay.reg_sel = h[38] & 15u;
            for (int r = 0; r < 16; r++)
                ay_write_reg((u8)r, h[39 + r]);
        }
        pc = (u16)(h[32] | (h[33] << 8));
        for (u32 at = 32 + extra; at + 3 <= size;) {
            u32 n = W16(h + at);
            u8 page = h[at + 2];
            at += 3;
            u32 length = n == 0xFFFF ? 0x4000 : n;
            if (at + length > size)
                return "a .z80 file cut short";
            int bank = -1;
            if (snap_128) {
                if (page >= 3 && page <= 10)
                    bank = page - 3;
            } else {
                bank = (page == 8) ? 5 : (page == 4) ? 2 : (page == 5) ? 0 : -1;
            }
            if (bank >= 0) {
                if (n == 0xFFFF)
                    for (u32 i = 0; i < 0x4000; i++)
                        M->ram[bank][i] = h[at + i];
                else
                    unpack_z80_page(h + at, n, M->ram[bank], 0x4000);
            }
            at += length;
        }
        rebuild_map();
    } else {
        setup_timing(0);
        port_7ffd = 0x30u;
        rebuild_map();
        u8 tmp[0xC000];
        for (u32 i = 0; i < sizeof(tmp); i++) tmp[i] = 0;
        if (flags & 0x20) {
            unpack_z80_page(h + 30, size - 30, tmp, 0xC000);
        } else {
            if (size < 30 + 0xC000)
                return "a .z80 file cut short";
            for (u32 i = 0; i < 0xC000; i++)
                tmp[i] = h[30 + i];
        }
        for (u32 i = 0; i < 0x4000; i++) {
            M->ram[5][i] = tmp[i];
            M->ram[2][i] = tmp[0x4000 + i];
            M->ram[0][i] = tmp[0x8000 + i];
        }
    }

    cpu.af.b.h = h[0], cpu.af.b.l = h[1];
    cpu.bc.w = (u16)W16(h + 2), cpu.hl.w = (u16)W16(h + 4);
    cpu.pc.w = pc;
    cpu.sp.w = (u16)W16(h + 8);
    cpu.i = h[10];
    cpu.r = h[11] & 0x7F, cpu.r7 = (u8)((flags & 1) << 7);
    border = (flags >> 1) & 7;
    cpu.de.w = (u16)W16(h + 13);
    cpu.bc2 = (u16)W16(h + 15), cpu.de2 = (u16)W16(h + 17), cpu.hl2 = (u16)W16(h + 19);
    cpu.af2 = (u16)(h[21] << 8 | h[22]);
    cpu.iy.w = (u16)W16(h + 23), cpu.ix.w = (u16)W16(h + 25);
    cpu.iff1 = h[27] ? 1 : 0, cpu.iff2 = h[28] ? 1 : 0;
    cpu.im = h[29] & 3;
    char *p = put(info, snap_128 ? "a 128K .z80 snapshot, version " : "a .z80 snapshot, version ");
    put_number(p, (u32)version);
    return 0;
}

static const char *snapshot_sna(const u8 *h, u32 size)
{
    int snap_128 = (size == 131103u || size == 147487u);
    if (size != 27u + 0xC000u && !snap_128)
        return "not a 48K or 128K .sna snapshot (expected 49179 or 131103 bytes)";

    cpu.i = h[0];
    cpu.hl2 = (u16)W16(h + 1), cpu.de2 = (u16)W16(h + 3), cpu.bc2 = (u16)W16(h + 5), cpu.af2 = (u16)W16(h + 7);
    cpu.hl.w = (u16)W16(h + 9), cpu.de.w = (u16)W16(h + 11), cpu.bc.w = (u16)W16(h + 13);
    cpu.iy.w = (u16)W16(h + 15), cpu.ix.w = (u16)W16(h + 17);
    cpu.iff1 = cpu.iff2 = (h[19] & 4) ? 1 : 0;
    cpu.r = h[20] & 0x7F, cpu.r7 = h[20] & 0x80;
    cpu.af.w = (u16)W16(h + 21);
    cpu.sp.w = (u16)W16(h + 23);
    cpu.im = h[25] & 3;
    border = h[26] & 7;

    if (!snap_128) {
        setup_timing(0);
        port_7ffd = 0x30u;
        for (u32 i = 0; i < 0x4000u; i++) {
            M->ram[5][i] = h[27u + i];
            M->ram[2][i] = h[27u + 0x4000u + i];
            M->ram[0][i] = h[27u + 0x8000u + i];
        }
        rebuild_map();
        u16 sp = cpu.sp.w;
        u8 lo = zx_peek(sp);
        sp++;
        cpu.pc.w = (u16)(lo | ((u16)zx_peek(sp) << 8));
        cpu.sp.w = (u16)(cpu.sp.w + 2);
        put(info, "a .sna snapshot");
        return 0;
    }

    /* 128K .sna: 27 + 49152 (banks 5, 2, top_bank) + 2B PC + 1B port_7ffd + 1B trdos + remaining 5 or 6 banks */
    setup_timing(1);
    u32 ext = 27u + 0xC000u;
    cpu.pc.w = (u16)W16(h + ext);
    port_7ffd = h[ext + 2];
    trdos_active = h[ext + 3] ? 1u : 0u;
    u8 top_bank = port_7ffd & 7u;
    for (u32 i = 0; i < 0x4000u; i++) {
        M->ram[5][i] = h[27u + i];
        M->ram[2][i] = h[27u + 0x4000u + i];
        M->ram[top_bank][i] = h[27u + 0x8000u + i];
    }
    u32 pos = ext + 4u;
    for (u8 b = 0; b < 8u; b++) {
        if (b == 5u || b == 2u || b == top_bank) {
            if (size == 147487u && b == top_bank && b != 5u && b != 2u)
                pos += 0x4000u;
            continue;
        }
        if (pos + 0x4000u <= size) {
            for (u32 i = 0; i < 0x4000u; i++)
                M->ram[b][i] = h[pos + i];
            pos += 0x4000u;
        }
    }
    rebuild_map();
    put(info, "a 128K .sna snapshot");
    return 0;
}

static const char *load_trd(const u8 *f, u32 size)
{
    if (size < 0x900u || size > TRD_MAX)
        return "not a valid .trd disk image (expected 2.25 KB .. 640 KB)";
    for (u32 i = 0; i < TRD_MAX; i++)
        M->trd[i] = (i < size) ? f[i] : 0;
    if (M->trd[0x8E7] != 0x10u)
        return "not a TR-DOS .trd image (missing 0x10 signature at 0x8E7)";
    has_trd = 1;
    trd_dirty = 0;
    return 0;
}

static const char *load_scl(const u8 *f, u32 size)
{
    static const char sig[8] = {'S','I','N','C','L','A','I','R'};
    if (size < 9u)
        return "a .scl file shorter than its header";
    for (int i = 0; i < 8; i++)
        if (f[i] != (u8)sig[i])
            return "not a .scl disk archive (missing SINCLAIR signature)";
    u32 nfiles = f[8];
    if (nfiles > 128u || size < 9u + nfiles * 14u)
        return "corrupt .scl file header";

    for (u32 i = 0; i < TRD_MAX; i++)
        M->trd[i] = 0;

    u32 dpos = 9u + nfiles * 14u;
    u32 cur_lsec = 16u;                 /* Track 1, Sector 0 */
    for (u32 idx = 0; idx < nfiles; idx++) {
        const u8 *sh = f + 9u + idx * 14u;
        u8 *dh = M->trd + idx * 16u;
        for (int k = 0; k < 14; k++)
            dh[k] = sh[k];
        dh[14] = (u8)(cur_lsec & 15u);
        dh[15] = (u8)(cur_lsec >> 4);
        u32 bytes = (u32)sh[13] * 256u;
        u32 dst_off = cur_lsec * 256u;
        if (dst_off + bytes > TRD_MAX)
            return ".scl files exceed 640 KB TR-DOS disk capacity";
        for (u32 b = 0; b < bytes; b++)
            M->trd[dst_off + b] = (dpos + b < size) ? f[dpos + b] : 0;
        dpos += bytes;
        cur_lsec += sh[13];
    }

    u32 free_sec = (cur_lsec < 2560u) ? (2560u - cur_lsec) : 0u;
    M->trd[0x8E1] = (u8)(cur_lsec & 15u);
    M->trd[0x8E2] = (u8)(cur_lsec >> 4);
    M->trd[0x8E3] = 0x16u;              /* 80 tracks, double-sided */
    M->trd[0x8E4] = (u8)nfiles;
    M->trd[0x8E5] = (u8)(free_sec & 0xFFu);
    M->trd[0x8E6] = (u8)(free_sec >> 8);
    M->trd[0x8E7] = 0x10u;              /* TR-DOS ID */
    static const char lbl[8] = {'S','C','L','_','D','I','S','K'};
    for (int k = 0; k < 8; k++)
        M->trd[0x8F5 + k] = (u8)lbl[k];

    has_trd = 1;
    trd_dirty = 0;
    return 0;
}

const char *zx_load(const u8 *rom16k, u8 *file, u32 size, const char *name)
{
    build_clean_roms();

    if (rom16k) {
        if (rom16k[0] != 0xF3 || rom16k[1] != 0xAF)
            return "no 48K ROM (its first bytes are DI, XOR A)";
        ext_rom48 = rom16k;
        using_builtin_rom = 0;
    } else if (has_ext_128) {
        ext_rom48 = 0;
        using_builtin_rom = 0;
    } else {
        ext_rom48 = 0;
        using_builtin_rom = 1;
    }

    blocks = 0;
    has_trd = 0;
    trd_dirty = 0;
    const char *why = 0;
    int tape = 0, disk = 0;

    if (file && (ends_with(name, ".tap") || ends_with(name, ".tzx"))) {
        why = ends_with(name, ".tap") ? load_tap(file, size) : load_tzx(file, size);
        if (why) {
            blocks = 0;
            return why;
        }
        tape = 1;
    } else if (file && (ends_with(name, ".trd") || ends_with(name, ".scl"))) {
        why = ends_with(name, ".trd") ? load_trd(file, size) : load_scl(file, size);
        if (why)
            return why;
        disk = 1;
    }

    zx_reset();

    if (tape) {
        u32 bytes = 0;
        for (int i = 0; i < blocks; i++)
            bytes += M->block_n[i];
        char *p = put(info, using_builtin_rom ? "a tape (built-in loader), " : "a tape, ");
        p = put_number(p, (u32)blocks);
        p = put(p, blocks == 1 ? " block (" : " blocks (");
        p = put_number(p, (bytes + 1023) >> 10);
        put(p, using_builtin_rom ? " KB)" : " KB); LOAD \"\" is typed");
        return 0;
    }
    if (disk) {
        /* If external 48/128 ROM was provided without external trdos.rom, boot disk directly */
        if (!using_builtin_rom && !has_ext_trdos)
            hle_boot_trd();
        u32 files_cnt = M->trd[0x8E4];
        char *p = put(info, ends_with(name, ".scl") ? "BetaDisk 128 (.scl), " : "BetaDisk 128 (.trd), ");
        p = put_number(p, files_cnt);
        put(p, files_cnt == 1 ? " file" : " files");
        return 0;
    }
    if (!file) {
        put(info, using_builtin_rom ? "Spectrum (built-in ROM)" : "BASIC");
        return 0;
    }
    if (ends_with(name, ".z80"))
        why = snapshot_z80(file, size);
    else if (ends_with(name, ".sna"))
        why = snapshot_sna(file, size);
    else
        why = "not a Spectrum file this player knows (.tap, .tzx, .z80, .sna, .trd, .scl)";
    if (why)
        zx_reset();
    return why;
}

const char *zx_info(void) { return info; }

u8 *zx_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return M->ram[5];
}

int zx_save_changed(void) { return 0; }

u32 zx_cpu_cycles(void)
{
    return cycles_hi + (u32)cpu.cycles;
}

int zx_jammed(void)
{
    return cpu.halted && !cpu.iff1;
}

void zx_audio_rate(u32 hz)
{
    sample_rate = hz;
    audio_frac = 0;
    audio_count = 0;
    audio_last_cyc = cpu.cycles;
    beep_dc = 0;
}

int zx_audio(s16 *out, int max)
{
    int n = audio_count < max ? audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    audio_count = 0;
    return n;
}

struct z80 *zx_cpu(void) { return &cpu; }

u8 zx_peek(u16 a)
{
    return ram_peek_fast(a);
}

u8 zx_port_7ffd(void)
{
    return port_7ffd;
}
