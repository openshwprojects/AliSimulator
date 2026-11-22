/* Nintendo Pokemon Mini (.min) emulator for ALi M3801/S3811 (v4).
 * Adapted for bare-metal MIPS32EL (zero .bss, KSEG0(EMU_RAM_PHYS) scratch, 48 kHz piezo PWM audio)
 * from JustBurn's PokeMini + FreeBIOS.
 */
#pragma GCC optimize("O2")
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

#include "pokemini.h"
#ifndef PM_HOST
#include "hw.h"
#endif

typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;

#define INLINE inline __attribute__((always_inline))

#define PM_RING_MASK 4095u
#define PM_MAX_ROM   0x200000u          /* 2 MB max Pokemon Mini cartridge */

struct pm_ws {
    uint8_t bios[4096];                 /* $000000..$000FFF: 4 KB BIOS */
    uint8_t ram[8192];                  /* $001000..$0020FF: 4 KB RAM + 256 B IO */
    uint8_t eeprom[8192];               /* 8 KB I2C EEPROM (.sav) */
    uint8_t lcd_data[256 * 9];          /* 132x65 GDDRAM pages */
    uint8_t lcd_pix_d[96 * 64];         /* Digital 0/1 pixels */
    uint8_t lcd_pix_a[96 * 64];         /* Analog 0..255 intensity */
    uint8_t lcd_pix_s[96 * 64];         /* 4-frame persistence history */
    int16_t snd_ring[PM_RING_MASK + 1u];
    uint16_t lcd_pal[256];              /* RGB15 (0bbbbbgggggrrrrr) ramp */
    uint8_t rom[PM_MAX_ROM];            /* Power-of-2 padded cartridge ROM */
};

#ifdef PM_HOST
static struct pm_ws pm_host_ws;
#define WS (&pm_host_ws)
#else
#define WS ((struct pm_ws *)KSEG0(EMU_RAM_PHYS))
#endif

#define PM_BIOS (WS->bios)
#define PM_RAM  (WS->ram)
#define PM_IO   (&WS->ram[0x1000])
#define PM_ROM  (WS->rom)
#define EEPROM  (WS->eeprom)

static void pm_zero(void *dst, uint32_t n)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++) p[i] = 0;
}
static void pm_fill(void *dst, uint8_t v, uint32_t n)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0; i < n; i++) p[i] = v;
}
static void pm_copy(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}


static const uint8_t FreeBIOS[4096] =
{
	0x9A,0x00,0xAB,0x00,0xAB,0x00,0x2F,0x02,0x41,0x02,0x53,0x02,0x65,0x02,0x77,0x02,
	0x89,0x02,0x9B,0x02,0xAD,0x02,0xBF,0x02,0xD1,0x02,0xE3,0x02,0xF5,0x02,0x07,0x03,
	0x19,0x03,0xAB,0x00,0xAB,0x00,0x60,0x04,0x2B,0x03,0xF1,0x03,0x3D,0x03,0x4F,0x03,
	0x61,0x03,0x73,0x03,0x85,0x03,0x97,0x03,0xA9,0x03,0xBB,0x03,0xCD,0x03,0xDF,0x03,
	0xF1,0xFF,0x9E,0x04,0x60,0x04,0x60,0x04,0xE4,0x04,0x60,0x04,0x0D,0x05,0x24,0x05,
	0x45,0x05,0x4C,0x05,0x5D,0x05,0x7C,0x05,0x92,0x05,0x9F,0x05,0xBB,0x05,0x60,0x04,
	0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,
	0x60,0x04,0xD6,0x05,0xE3,0x05,0x60,0x04,0x60,0x04,0xF0,0x05,0x00,0x06,0x66,0x06,
	0x7A,0x06,0x8A,0x06,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,0x60,0x04,
	0x60,0x04,0x60,0x04,0x60,0x04,0x00,0x00,0x98,0x06,0xB4,0x20,0x38,0xCE,0xCD,0xDD,
	0x08,0x02,0xD9,0x08,0x01,0xDD,0x00,0x7C,0xDD,0x02,0x00,0x9F,0xC0,0xB4,0x20,0x38,
	0xCE,0xCD,0xCE,0xCE,0xCE,0xCF,0xCF,0x6E,0x00,0x20,0xDD,0x80,0x00,0xCE,0xC4,0x01,
	0xF3,0x01,0x00,0xD9,0x00,0x03,0xD9,0x01,0x30,0xD9,0x02,0xC0,0xF2,0xE1,0x00,0xC6,
	0xA0,0x06,0xBE,0x82,0x20,0x79,0x84,0x79,0x85,0x79,0x86,0x79,0x87,0x79,0x88,0x79,
	0x89,0x38,0xC6,0x00,0x10,0x60,0x92,0xD6,0x00,0x20,0xEF,0xF9,0xFF,0xF2,0x05,0x01,
	0xDD,0xFE,0xAF,0xF2,0x1D,0x01,0xD9,0x80,0x0A,0xD9,0x81,0x01,0xDC,0x10,0x20,0xEF,
	0x40,0x00,0xF2,0x2F,0x00,0xEF,0x3A,0x00,0x38,0xDD,0x80,0x00,0xDD,0x81,0x07,0x78,
	0x82,0x78,0x83,0xD8,0x01,0xEF,0xC6,0x00,0x10,0x60,0x92,0xD6,0x00,0x20,0xEF,0xF9,
	0xFF,0xC4,0x00,0x00,0xCF,0xE4,0xCF,0xE8,0xCF,0xEC,0x4C,0x52,0xB0,0xFF,0x9C,0xC0,
	0xF3,0xD0,0x1F,0xCE,0xD0,0x00,0x21,0x32,0x4D,0xF8,0xCE,0xD0,0x01,0x21,0x32,0x4E,
	0xF8,0xB1,0x03,0xA0,0xB0,0x01,0xC6,0x7D,0x13,0xB1,0x03,0xF2,0x51,0x00,0xC6,0x88,
	0x13,0xB1,0x04,0xF2,0x49,0x00,0xDC,0x10,0x20,0xEE,0x0B,0x00,0xC6,0x94,0x13,0xB0,
	0x08,0xB1,0x04,0xF2,0x39,0x00,0xF2,0xCB,0xFF,0xEE,0x0B,0x00,0xC6,0xA0,0x13,0xB0,
	0x0C,0xB1,0x04,0xF2,0x29,0x00,0xF2,0x2C,0x00,0xC6,0x94,0x13,0xB0,0x00,0xB1,0x04,
	0xF2,0x17,0x00,0xF2,0x1F,0x00,0xA8,0xF5,0xBB,0xC6,0xA0,0x13,0xB0,0x00,0xB1,0x04,
	0xF2,0x07,0x00,0xF2,0x0F,0x00,0xF3,0x6A,0xFF,0x60,0x92,0xF5,0xFD,0xF8,0x60,0x92,
	0x80,0xF5,0xFC,0xF8,0xB0,0xFF,0xB1,0xFF,0xF5,0xFF,0x88,0xEF,0xF9,0xFF,0xF8,0xB1,
	0x00,0xDD,0x10,0x08,0xD8,0x19,0xCF,0x79,0x20,0xDD,0x21,0x30,0xDD,0x22,0x02,0x79,
	0x23,0xDD,0x24,0x02,0x79,0x25,0x79,0x26,0x79,0x40,0x79,0x44,0xDD,0x50,0xFF,0x79,
	0x51,0x79,0x54,0x79,0x55,0xD9,0x60,0x0C,0xD8,0x61,0xFB,0xD9,0x61,0x08,0xD9,0x61,
	0x04,0xDD,0x61,0x20,0xDD,0x60,0x32,0x79,0x62,0x79,0x70,0x79,0x71,0xDD,0xFE,0x81,
	0xDD,0xFE,0x1F,0xF8,0xA1,0xC5,0xFE,0x20,0xB5,0xE3,0xB5,0xA4,0xB5,0xAD,0xB5,0x00,
	0xB5,0x10,0xB5,0xEE,0xB5,0x40,0xB5,0xA2,0xB5,0xA0,0xB5,0xC0,0xB5,0xA6,0xB5,0x2F,
	0xA9,0xF8,0xC5,0xFE,0x20,0xB5,0xE3,0xB3,0xB0,0x6B,0xB5,0x00,0xB5,0x10,0xB1,0x60,
	0x91,0xDD,0xFF,0x00,0xF5,0xFC,0x99,0x83,0xCE,0xBE,0xB8,0xEF,0xEC,0xFF,0xF8,0xA5,
	0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x00,0x02,0xAC,0xAD,0xF3,0xC8,
	0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xEE,0x01,0xAC,0xAD,
	0xF3,0xBC,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xDC,0x01,
	0xAC,0xAD,0xF3,0xB0,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,
	0xCA,0x01,0xAC,0xAD,0xF3,0xA4,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,
	0x20,0xEA,0xB8,0x01,0xAC,0xAD,0xF3,0x98,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,
	0xDC,0x01,0x20,0xEA,0xA6,0x01,0xAC,0xAD,0xF3,0x8C,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,
	0xB4,0x20,0xDC,0x01,0x20,0xEA,0x94,0x01,0xAC,0xAD,0xF3,0x80,0x1E,0xA5,0xA4,0xCE,
	0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x82,0x01,0xAC,0xAD,0xF3,0x74,0x1E,0xA5,
	0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x70,0x01,0xAC,0xAD,0xF3,0x68,
	0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x5E,0x01,0xAC,0xAD,
	0xF3,0x5C,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x4C,0x01,
	0xAC,0xAD,0xF3,0x50,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,
	0x3A,0x01,0xAC,0xAD,0xF3,0x44,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,
	0x20,0xEA,0x28,0x01,0xAC,0xAD,0xF3,0x38,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,
	0xDC,0x01,0x20,0xEA,0x16,0x01,0xAC,0xAD,0xF3,0x2C,0x1E,0xA5,0xA4,0xCE,0xC5,0x00,
	0xB4,0x20,0xDC,0x01,0x20,0xEA,0x04,0x01,0xAC,0xAD,0xF3,0x62,0x1E,0xA5,0xA4,0xCE,
	0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xF2,0x00,0xAC,0xAD,0xF3,0x14,0x1E,0xA5,
	0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xE0,0x00,0xAC,0xAD,0xF3,0x08,
	0x1E,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xCE,0x00,0xAC,0xAD,
	0xF3,0xFC,0x1D,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0xBC,0x00,
	0xAC,0xAD,0xF3,0xF0,0x1D,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,
	0xAA,0x00,0xAC,0xAD,0xF3,0xE4,0x1D,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,
	0x20,0xEA,0x98,0x00,0xAC,0xAD,0xF3,0xD8,0x1D,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,
	0xDC,0x01,0x20,0xEA,0x86,0x00,0xAC,0xAD,0xF3,0xCC,0x1D,0xA5,0xA4,0xCE,0xC5,0x00,
	0xB4,0x20,0xDC,0x01,0x20,0xEA,0x74,0x00,0xAC,0xAD,0xF3,0xC0,0x1D,0xA5,0xA4,0xCE,
	0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x62,0x00,0xAC,0xAD,0xF3,0xB4,0x1D,0xA5,
	0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEA,0x50,0x00,0xAC,0xAD,0xF3,0xA8,
	0x1D,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x01,0x20,0xEF,0x2A,0x00,0xDC,0x01,
	0x10,0xEF,0xA8,0xFC,0xDC,0x71,0x04,0xEE,0x0D,0x00,0xDC,0x02,0x40,0xEE,0x07,0x00,
	0xD8,0x71,0xFB,0xD9,0x02,0x80,0xDC,0x01,0x80,0xEE,0x11,0x00,0xDC,0x02,0x20,0xEF,
	0x14,0x00,0xAC,0xAD,0xF3,0xD7,0x1B,0xAC,0xAD,0xF3,0x31,0x1D,0xD9,0x01,0x20,0xDC,
	0x02,0x20,0xEF,0xF3,0xFF,0xDD,0x29,0x80,0xAC,0xAD,0xF9,0xDC,0x71,0x04,0xEE,0x0D,
	0x00,0xDC,0x02,0x40,0xEE,0x07,0x00,0xD8,0x71,0xFB,0xD9,0x02,0x80,0xDC,0x01,0x80,
	0xEE,0x0A,0x00,0xCF,0x68,0x03,0x00,0xAC,0xAD,0xF3,0xA2,0x1B,0xD9,0x01,0x20,0xF8,
	0xF9,0xD8,0x80,0xF7,0xDD,0xFE,0xAE,0xDD,0xFE,0xAC,0xDD,0xFE,0x28,0xDD,0xFE,0xA5,
	0xD8,0x02,0xE3,0xD8,0x81,0xFE,0xD9,0x02,0x01,0xD9,0x24,0x02,0xD9,0x21,0x30,0xD8,
	0x01,0xDF,0xD8,0x02,0xE3,0xA7,0x9F,0x80,0xCE,0xAE,0xAF,0xD9,0x02,0x10,0xD9,0x81,
	0x01,0xF2,0x61,0xFD,0xDD,0xFE,0xAF,0xD8,0x02,0xDF,0xD9,0x00,0x03,0xF8,0xA5,0xA4,
	0x9F,0xC0,0xCE,0xC5,0x00,0xB4,0x20,0x4C,0x80,0x44,0x21,0x22,0x0C,0xA0,0x4C,0x23,
	0x44,0x24,0xA0,0x4C,0x25,0x44,0x26,0xA0,0xDD,0x23,0x00,0xDD,0x24,0x00,0xDD,0x25,
	0x80,0xDD,0x26,0x00,0xD9,0x21,0x0C,0xDD,0x29,0x80,0xDD,0x80,0x00,0xF2,0x92,0xFF,
	0xA8,0x79,0x25,0x78,0x26,0xA8,0x79,0x23,0x78,0x24,0xA8,0x79,0x80,0x22,0xF3,0x78,
	0x21,0xAC,0xAD,0xF9,0x9F,0xC0,0xCF,0x6E,0x00,0x20,0xCE,0xC5,0x00,0xB4,0x20,0xF2,
	0xBE,0xFC,0xDD,0x23,0x00,0xDD,0x24,0x00,0xDD,0x25,0x80,0xDD,0x26,0x00,0xDD,0x29,
	0x80,0xDD,0x80,0x00,0xDD,0x21,0x0C,0xF2,0x58,0xFF,0xF3,0x9F,0xFB,0xAF,0xA5,0xA1,
	0xCE,0xC5,0x00,0xC5,0x00,0x20,0xCE,0x84,0xCE,0x84,0xCE,0x25,0x03,0xCE,0x2C,0xA9,
	0xAD,0xF3,0x23,0x00,0xF2,0x27,0x00,0xAF,0xA7,0xEE,0x0A,0x00,0x32,0x3F,0xEE,0x0D,
	0x00,0x80,0xF3,0x0C,0x00,0x28,0xEE,0x05,0x00,0x88,0xF3,0x04,0x00,0xB0,0xFF,0xF9,
	0xF2,0xCC,0xFF,0x38,0xF9,0xAF,0xF2,0x05,0x00,0xF3,0x13,0x00,0xAF,0xA5,0xA4,0xCE,
	0xC5,0x00,0xB4,0x20,0x44,0x00,0xCE,0x8C,0xCE,0x8C,0xAC,0xAD,0xF8,0xAF,0xA5,0xA4,
	0xCE,0xC5,0x00,0xB4,0x20,0x48,0xDC,0x80,0x08,0xA7,0xD8,0x80,0xF7,0xDD,0xFE,0x81,
	0x79,0xFE,0xAF,0xEE,0x04,0x00,0xD9,0x80,0x08,0xAC,0xAD,0xF8,0xA5,0xA4,0xCE,0xC5,
	0x00,0xB4,0x20,0xF2,0x6F,0xFC,0xDD,0xFE,0xAF,0xD9,0x80,0x04,0xD9,0x81,0x01,0xAC,
	0xAD,0xF9,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xF2,0x59,0xFC,0xAC,0xAD,0xF9,0xA5,
	0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xD8,0x80,0xF7,0xDD,0xFE,0xAE,0xDD,0xFE,0xAC,0xDD,
	0xFE,0x28,0xDD,0xFE,0xA5,0xD8,0x81,0xFE,0xAC,0xAD,0xF9,0xA5,0xA4,0xCE,0xC5,0x00,
	0xB4,0x20,0x9F,0xC0,0xDC,0x01,0x80,0xEF,0x0A,0x00,0xD9,0x01,0x80,0xD9,0x01,0x40,
	0xD8,0x01,0xDF,0xAC,0xAD,0xF9,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xD8,0x00,0xFC,
	0xAC,0xAD,0xF9,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xD9,0x00,0x03,0xAC,0xAD,0xF9,
	0xAF,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xDC,0x53,0x02,0x9E,0x01,0xAC,0xAD,0xF8,
	0xA5,0xA4,0xCE,0xC5,0x00,0xB4,0x20,0xA6,0xA2,0xA3,0xA1,0xCF,0xB1,0x9F,0xC0,0x46,
	0x96,0x01,0xCE,0xC1,0xEE,0x0E,0x00,0xC2,0x0A,0x00,0x5E,0x9A,0x56,0x9A,0xA1,0x4E,
	0x9A,0xF3,0x04,0x00,0xC2,0x07,0x00,0xA0,0x4E,0x9A,0x46,0x9A,0x5E,0x9A,0x56,0x9A,
	0xCE,0xCF,0xCF,0xED,0x46,0x9A,0x5E,0x9A,0x56,0xCE,0xCE,0xCF,0xE9,0xD9,0x02,0x80,
	0xB6,0xFF,0xD9,0x02,0x80,0x47,0xD9,0x02,0x80,0x31,0xA8,0xCE,0xC3,0xEE,0x0A,0x00,
	0xAF,0x51,0xA8,0x58,0x41,0xA7,0xF2,0x0B,0x00,0xA8,0x22,0x01,0xA9,0xAB,0xAA,0xAE,
	0xAC,0xAD,0xF9,0xCE,0xCC,0xF4,0xA5,0xA1,0xCE,0xC5,0x00,0xC5,0x81,0x20,0xCE,0x25,
	0xF1,0x22,0x07,0xCE,0x84,0xCE,0x2C,0xA9,0xAD,0xF9,0xA5,0xA4,0xCE,0xC5,0x00,0xB4,
	0x20,0x44,0x81,0xCE,0x8C,0x22,0x07,0xAC,0xAD,0xF9,0xAF,0xA5,0xA4,0xCE,0xC5,0x00,
	0xB4,0x20,0xDC,0x01,0x08,0xAC,0xAD,0xF8,0xB7,0x02,0xF5,0xFF,0xB7,0x00,0xF9,0xFF,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xF8,0x04,0x82,0xE1,0xE1,0x31,0x31,
	0x39,0x39,0x39,0x39,0x39,0x39,0x31,0x31,0xE1,0xE1,0x82,0x06,0xFA,0x04,0xF8,0x00,
	0xFE,0x82,0xEA,0x3A,0xFE,0x82,0xEA,0x96,0xFC,0xC7,0xAA,0xBB,0xFF,0xC7,0xAA,0xBA,
	0xFE,0x82,0xAA,0xD6,0xFE,0x8A,0xFE,0xC6,0xBB,0xC7,0xFD,0xB6,0xAB,0xAB,0xDA,0x7E,
	0x7C,0x7C,0x40,0x40,0x00,0x38,0x7C,0x44,0x7C,0x38,0x00,0x3C,0x7C,0x20,0x7C,0x3C,
	0x00,0x00,0x7C,0x7C,0x7C,0x74,0x6C,0x54,0x64,0x44,0x44,0x44,0x44,0x6C,0x38,0x00,
	0x7C,0x7C,0x08,0x10,0x7C,0x7C,0x00,0x38,0x7C,0x44,0x7C,0x38,0x00,0x00,0x00,0x38,
	0x44,0x44,0x00,0x78,0x14,0x14,0x78,0x00,0x7C,0x14,0x14,0x68,0x00,0x04,0x7C,0x04,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0x20,0x20,0x20,0x20,0x46,0x72,0x65,0x65,0x77,0x61,0x72,0x65,0x20,0x20,0x20,0x20,
	0x50,0x6F,0x6B,0x65,0x6D,0x6F,0x6E,0x4D,0x69,0x6E,0x69,0x20,0x42,0x49,0x4F,0x53,
	0x20,0x20,0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x20,0x20,0x31,0x2E,0x33,0x20,0x20,
	0x20,0x62,0x79,0x20,0x54,0x65,0x61,0x6D,0x20,0x50,0x6F,0x6B,0x65,0x6D,0x65,0x20,
};




typedef union {
	struct {
		uint8_t L;
		uint8_t H;
		uint8_t I;
		uint8_t X;
	} B;
	struct {
		uint16_t L;
		uint16_t H;
	} W;
	uint32_t D;
} MinxRegx;



#define MINX_FLAG_ZERO    	0x01
#define MINX_FLAG_CARRY   	0x02
#define MINX_FLAG_OVERFLOW	0x04
#define MINX_FLAG_SIGN    	0x08
#define MINX_FLAG_BCD     	0x10
#define MINX_FLAG_NIBBLE  	0x20
#define MINX_FLAG_INTFLG  	0x40
#define MINX_FLAG_INTOFF  	0x80

#define MINX_FLAG_SAVE_NUL	0xF0
#define MINX_FLAG_SAVE_O  	0xF4
#define MINX_FLAG_SAVE_CO 	0xF6
#define MINX_FLAG_SAVE_COS	0xFE

// Status reasons
enum {
	MINX_STATUS_NORMAL = 0,   // Normal operation
	MINX_STATUS_HALT   = 1,   // CPU during HALT
	MINX_STATUS_STOP   = 2,   // CPU during STOP
	MINX_STATUS_IRQ    = 3    // Delay caused by hardware IRQ
};

// Signed 8-Bits to 16-Bits converter
static INLINE uint16_t S8_TO_16(int8_t a)
{
	return (a & 0x80) ? (0xFF00 | a) : a;
}

typedef struct {
	// Registers
	MinxRegx BA;			// Registers A, B
	MinxRegx HL;			// Registers L, H, I
	MinxRegx X;			// Registers X, XI
	MinxRegx Y;			// Registers Y, YI
	MinxRegx SP;			// Register SP
	MinxRegx PC;			// Registers PC, V
	MinxRegx N;			// for [N+#nn], I is written here too
	uint8_t U1;			// V Shadow 1
	uint8_t U2;			// V Shadow 2
	uint8_t F;			// Flags
	uint8_t E;			// Exception
	uint8_t IR;			// Last Instruction Register (for open-bus)
	uint8_t Shift_U;		// Shift U, set to 2 when: U modify, branch, return
	uint8_t Status;			// CPU Status (0 = Normal, 1 = Halt, 2 = Stoped, 3 = IRQ)
	uint8_t IRQ_Vector;		// IRQ Vector when Status is IRQ
	uint8_t Reserved[28];		// Reserved bytes
} TMinxCPU;

// CPU registers
static TMinxCPU MinxCPU;

// Callbacks (Must be coded by the user)
static uint8_t MinxCPU_OnRead(int cpu, uint32_t addr);
static void MinxCPU_OnWrite(int cpu, uint32_t addr, uint8_t data);
static void MinxCPU_OnIRQHandle(uint8_t flag, uint8_t shift_u);
static void MinxCPU_OnIRQAct(uint8_t intr);

// Functions
static int MinxCPU_Create(void);		// Create MinxCPU
static void MinxCPU_Destroy(void);		// Destroy MinxCPU
static void MinxCPU_Reset(int hardreset);	// Reset CPU


static __attribute__((noinline)) int MinxCPU_Exec(void);			// Execute 1 CPU instruction
static int MinxCPU_CallIRQ(uint8_t IRQ);	// Call an IRQ

// Helpers
static INLINE uint16_t ReadMem16(uint32_t addr)
{
	return MinxCPU_OnRead(1, addr) + (MinxCPU_OnRead(1, addr+1) << 8);
}

static INLINE void WriteMem16(uint32_t addr, uint16_t data)
{
	MinxCPU_OnWrite(1, addr, (uint8_t)data);
	MinxCPU_OnWrite(1, addr+1, data >> 8);
}

static INLINE uint8_t Fetch8(void)
{
	if (MinxCPU.PC.W.L & 0x8000) {
		// Banked area
		MinxCPU.IR = MinxCPU_OnRead(1, (MinxCPU.PC.W.L++ & 0x7FFF) | (MinxCPU.PC.B.I << 15));
	} else {
		// Unbanked area
		MinxCPU.IR = MinxCPU_OnRead(1, MinxCPU.PC.W.L++);
	}
	return MinxCPU.IR;
}

static INLINE uint16_t Fetch16(void)
{
	uint8_t LB = Fetch8();
	return (Fetch8() << 8) | LB;
}

static INLINE void Set_U(uint8_t val)
{
	if (val != MinxCPU.U2) MinxCPU.Shift_U = 2;
	MinxCPU.U1 = val;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
}

// Instruction exec. prototypes

static __attribute__((noinline)) int MinxCPU_ExecCE(void);
static __attribute__((noinline)) int MinxCPU_ExecCF(void);
static __attribute__((noinline)) int MinxCPU_ExecSPCE(void);
static __attribute__((noinline)) int MinxCPU_ExecSPCF(void);

// Instructions Macros

static INLINE uint8_t ADD8(uint8_t A, uint8_t B)
{
	register uint8_t RES;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	switch (MinxCPU.F & 0x30) {
	case 0x00: // Normal
		RES = A + B;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x80) != 0) && (((A ^ B) & 0x80) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 128) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0xFF;
	case 0x10: // BCD
		if ((uint8_t)((A & 15) + (B & 15)) >= 10) {
			RES = A + B + 6;
		} else {
			RES = A + B;
		}
		if (RES >= 0xA0) RES += 0x60;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;	
		return RES & 0xFF;
	case 0x20: // Nibble
		RES = (A & 15) + (B & 15);
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x8) != 0) && (((A ^ B) & 0x8) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 8) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0x0F;
	default:   // BCD and Nibble
		if ((uint8_t)((A & 15) + (B & 15)) >= 10) {
			RES = (A & 15) + (B & 15) + 6;
		} else {
			RES = (A & 15) + (B & 15);
		}
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		return RES & 0x0F;
	}
}

static INLINE uint16_t ADD16(uint16_t A, uint16_t B)
{
	register uint16_t RES;
	RES = A + B;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;
	if ((((A ^ RES) & 0x8000) != 0) && (((A ^ B) & 0x8000) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	if (RES & 0x8000) MinxCPU.F |= MINX_FLAG_SIGN;
	return (uint16_t)RES;
}

static INLINE uint8_t ADC8(uint8_t A, uint8_t B)
{
	register uint8_t RES;
	register uint8_t CARRY = (MinxCPU.F & MINX_FLAG_CARRY) ? 1 : 0;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	switch (MinxCPU.F & 0x30) {
	case 0x00: // Normal
		RES = A + B + CARRY;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x80) != 0) && (((A ^ B) & 0x80) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 128) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0xFF;
	case 0x10: // BCD
		if ((uint8_t)((A & 15) + (B & 15) + CARRY) >= 10) {
			RES = A + B + CARRY + 6;
		} else {
			RES = A + B + CARRY;
		}
		if (RES >= 0xA0) RES += 0x60;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;	
		return RES & 0xFF;
	case 0x20: // Nibble
		RES = (A & 15) + (B & 15) + CARRY;
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x8) != 0) && (((A ^ B) & 0x8) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 8) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0x0F;
	default:   // BCD and Nibble
		if ((uint8_t)((A & 15) + (B & 15) + CARRY) >= 10) {
			RES = (A & 15) + (B & 15) + CARRY + 6;
		} else {
			RES = (A & 15) + (B & 15) + CARRY;
		}
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		return RES & 0x0F;
	}
}

static INLINE uint16_t ADC16(uint16_t A, uint16_t B)
{
	register uint16_t RES;
	RES = A + B + ((MinxCPU.F & MINX_FLAG_CARRY) ? 1 : 0);
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (RES < A) MinxCPU.F |= MINX_FLAG_CARRY;
	if ((((A ^ RES) & 0x8000) != 0) && (((A ^ B) & 0x8000) == 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	if (RES & 0x8000) MinxCPU.F |= MINX_FLAG_SIGN;
	return (uint16_t)RES;
}

static INLINE uint8_t SUB8(uint8_t A, uint8_t B)
{
	register uint8_t RES;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	switch (MinxCPU.F & 0x30) {
	case 0x00: // Normal
		RES = A - B;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x80) != 0) && (((A ^ B) & 0x80) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 128) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0xFF;
	case 0x10: // BCD
		if ((uint8_t)((A & 15) - (B & 15)) >= 10) {
			RES = A - B - 6;
		} else {
			RES = A - B;
		}
		if (RES >= 0xA0) RES -= 0x60;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;	
		return RES & 0xFF;
	case 0x20: // Nibble
		RES = (A & 15) - (B & 15);
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x8) != 0) && (((A ^ B) & 0x8) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 8) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0x0F;
	default:   // BCD and Nibble
		if ((uint8_t)((A & 15) - (B & 15)) >= 10) {
			RES = (A & 15) - (B & 15) - 6;
		} else {
			RES = (A & 15) - (B & 15);
		}
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		return RES & 0x0F;
	}
}

static INLINE uint16_t SUB16(uint16_t A, uint16_t B)
{
	register uint16_t RES;
	RES = A - B;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;
	if ((((A ^ RES) & 0x8000) != 0) && (((A ^ B) & 0x8000) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	if (RES & 0x8000) MinxCPU.F |= MINX_FLAG_SIGN;
	return (uint16_t)RES;
}

static INLINE uint8_t SBC8(uint8_t A, uint8_t B)
{
	register uint8_t RES;
	register uint8_t CARRY = (MinxCPU.F & MINX_FLAG_CARRY) ? 1 : 0;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	switch (MinxCPU.F & 0x30) {
	case 0x00: // Normal
		RES = A - B - CARRY;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x80) != 0) && (((A ^ B) & 0x80) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 128) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0xFF;
	case 0x10: // BCD
		if ((uint8_t)((A & 15) - (B & 15) - CARRY) >= 10) {
			RES = A - B - CARRY - 6;
		} else {
			RES = A - B - CARRY;
		}
		if (RES >= 0xA0) RES -= 0x60;
		if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;	
		return RES & 0xFF;
	case 0x20: // Nibble
		RES = (A & 15) - (B & 15) - CARRY;
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		if ((((A ^ RES) & 0x8) != 0) && (((A ^ B) & 0x8) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
		if (RES & 8) MinxCPU.F |= MINX_FLAG_SIGN;
		return RES & 0x0F;
	default:   // BCD and Nibble
		if ((uint8_t)((A & 15) - (B & 15) - CARRY) >= 10) {
			RES = (A & 15) - (B & 15) - CARRY - 6;
		} else {
			RES = (A & 15) - (B & 15) - CARRY;
		}
		if ((RES & 15) == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (RES >= 16) MinxCPU.F |= MINX_FLAG_CARRY;
		return RES & 0x0F;
	}
}

static INLINE uint16_t SBC16(uint16_t A, uint16_t B)
{
	register uint16_t RES;
	RES = A - B - ((MinxCPU.F & MINX_FLAG_CARRY) ? 1 : 0);
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (RES == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A < B) MinxCPU.F |= MINX_FLAG_CARRY;
	if ((((A ^ RES) & 0x8000) != 0) && (((A ^ B) & 0x8000) != 0)) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	if (RES & 0x8000) MinxCPU.F |= MINX_FLAG_SIGN;
	return (uint16_t)RES;
}

static INLINE uint8_t AND8(uint8_t A, uint8_t B)
{
	A &= B;
	MinxCPU.F &= MINX_FLAG_SAVE_CO;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 128) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t OR8(uint8_t A, uint8_t B)
{
	A |= B;
	MinxCPU.F &= MINX_FLAG_SAVE_CO;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 128) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t XOR8(uint8_t A, uint8_t B)
{
	A ^= B;
	MinxCPU.F &= MINX_FLAG_SAVE_CO;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 128) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t INC8(uint8_t A)
{
	A++;
	MinxCPU.F &= MINX_FLAG_SAVE_COS;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	return A;
}

static INLINE uint16_t INC16(uint16_t A)
{
	A++;
	MinxCPU.F &= MINX_FLAG_SAVE_COS;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	return A;
}

static INLINE uint8_t DEC8(uint8_t A)
{
	A--;
	MinxCPU.F &= MINX_FLAG_SAVE_COS;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	return A;
}

static INLINE uint16_t DEC16(uint16_t A)
{
	A--;
	MinxCPU.F &= MINX_FLAG_SAVE_COS;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	return A;
}

static INLINE void PUSH(uint8_t A)
{
	MinxCPU.SP.W.L--;
	MinxCPU_OnWrite(1, MinxCPU.SP.D, A);
}

static INLINE uint8_t POP(void)
{
	register uint8_t data;
	data = MinxCPU_OnRead(1, MinxCPU.SP.D);
	MinxCPU.SP.W.L++;
	return data;
}

static INLINE void CALLS(uint16_t OFFSET)
{
	PUSH(MinxCPU.PC.B.I);
	PUSH(MinxCPU.PC.B.H);
	PUSH(MinxCPU.PC.B.L);
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = MinxCPU.PC.W.L + OFFSET - 1;
}

static INLINE void JMPS(uint16_t OFFSET)
{
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = MinxCPU.PC.W.L + OFFSET - 1;
}

static INLINE void CALLU(uint16_t ADDR)
{
	PUSH(MinxCPU.PC.B.I);
	PUSH(MinxCPU.PC.B.H);
	PUSH(MinxCPU.PC.B.L);
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = ADDR;
}

static INLINE void JMPU(uint16_t ADDR)
{
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = ADDR;
}

static INLINE void JDBNZ(uint16_t OFFSET)
{
	MinxCPU.BA.B.H = DEC8(MinxCPU.BA.B.H);
	if (MinxCPU.BA.B.H != 0) {
		JMPS(OFFSET);
	}
}

static INLINE uint8_t SWAP(uint8_t A)
{
	return (A << 4) | (A >> 4);
}

static INLINE void RET(void)
{
	MinxCPU.PC.B.L = POP();
	MinxCPU.PC.B.H = POP();
	MinxCPU.PC.B.I = POP();
	Set_U(MinxCPU.PC.B.I);
}

static INLINE void RETI(void)
{
	MinxCPU.F = POP();
	MinxCPU.PC.B.L = POP();
	MinxCPU.PC.B.H = POP();
	MinxCPU.PC.B.I = POP();
	Set_U(MinxCPU.PC.B.I);
	MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
}

static INLINE void CALLX(uint16_t ADDR)
{
	PUSH(MinxCPU.PC.B.I);
	PUSH(MinxCPU.PC.B.H);
	PUSH(MinxCPU.PC.B.L);
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = ReadMem16((MinxCPU.HL.B.I << 16) + ADDR);
}

static INLINE void CALLI(uint16_t ADDR)
{
	PUSH(MinxCPU.PC.B.I);
	PUSH(MinxCPU.PC.B.H);
	PUSH(MinxCPU.PC.B.L);
	PUSH(MinxCPU.F);
	MinxCPU.F |= 0xC0;
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = ReadMem16(ADDR);
	MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
}

static INLINE void JMPI(uint16_t ADDR)
{
	PUSH(MinxCPU.F);
	MinxCPU.F |= 0xC0;
	MinxCPU.PC.B.I = MinxCPU.U1;
	MinxCPU.U2 = MinxCPU.U1;
	MinxCPU.PC.W.L = ReadMem16(ADDR);
	MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
}

static INLINE uint8_t SAL(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_CARRY;
	if ((!(A & 0x40)) != (!(A & 0x80))) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	A = A << 1;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t SHL(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_CARRY;
	A = A << 1;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t SAR(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (A & 0x01) MinxCPU.F |= MINX_FLAG_CARRY;
	A = (A & 0x80) | (A >> 1);
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t SHR(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x01) MinxCPU.F |= MINX_FLAG_CARRY;
	A = A >> 1;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t ROLC(uint8_t A)
{
	register uint8_t CARRY = (MinxCPU.F & MINX_FLAG_CARRY) ? 1 : 0;
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_CARRY;
	A = (A << 1) | CARRY;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t ROL(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_CARRY;
	A = (A << 1) | (A >> 7);
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t RORC(uint8_t A)
{
	register uint8_t CARRY = (MinxCPU.F & MINX_FLAG_CARRY) ? 0x80 : 0x00;
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x01) MinxCPU.F |= MINX_FLAG_CARRY;
	A = (A >> 1) | CARRY;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t ROR(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_O;
	if (A & 0x01) MinxCPU.F |= MINX_FLAG_CARRY;
	A = (A >> 1) | (A << 7);
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE uint8_t NOT(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_CO;
	A = A ^ 0xFF;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;	
}

static INLINE uint8_t NEG(uint8_t A)
{
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	A = -A;
	if (A == 0) MinxCPU.F |= MINX_FLAG_ZERO; else MinxCPU.F |= MINX_FLAG_CARRY;
	if (A == 0x80) MinxCPU.F |= MINX_FLAG_OVERFLOW;
	if (A & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	return A;
}

static INLINE void HALT(void)
{
	MinxCPU.Status = MINX_STATUS_HALT;
}

static INLINE void STOP(void)
{
	MinxCPU.Status = MINX_STATUS_STOP;
}

static INLINE void MUL(void)
{
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	MinxCPU.HL.W.L = (uint16_t)MinxCPU.HL.B.L * (uint16_t)MinxCPU.BA.B.L;
	if (MinxCPU.HL.W.L == 0) MinxCPU.F |= MINX_FLAG_ZERO;
	if (MinxCPU.HL.W.L & 0x8000) MinxCPU.F |= MINX_FLAG_SIGN;
}

static INLINE void DIV(void)
{
	uint16_t RES;
	MinxCPU.F &= MINX_FLAG_SAVE_NUL;
	if (MinxCPU.BA.B.L == 0)
		return;
	RES = MinxCPU.HL.W.L / MinxCPU.BA.B.L;
	if (RES < 256) {
		MinxCPU.HL.B.H = MinxCPU.HL.W.L % MinxCPU.BA.B.L;
		MinxCPU.HL.B.L = (uint8_t)RES;
		if (MinxCPU.HL.B.L == 0) MinxCPU.F |= MINX_FLAG_ZERO;
		if (MinxCPU.HL.B.L & 0x80) MinxCPU.F |= MINX_FLAG_SIGN;
	} else MinxCPU.F |= (MINX_FLAG_OVERFLOW | MINX_FLAG_SIGN);
}




/* I/O Register aliases in PM_RAM[0x1000..0x10FF] */
#define PMR_SYS_CTRL1    (PM_RAM[0x1000])
#define PMR_SYS_CTRL2    (PM_RAM[0x1001])
#define PMR_SYS_CTRL3    (PM_RAM[0x1002])
#define PMR_SEC_CTRL     (PM_RAM[0x1008])
#define PMR_SYS_BATT     (PM_RAM[0x1010])
#define PMR_TMR1_SCALE   (PM_RAM[0x1018])
#define PMR_TMR1_ENA_OSC (PM_RAM[0x1019])
#define PMR_TMR1_OSC     (PM_RAM[0x1019])
#define PMR_TMR2_SCALE   (PM_RAM[0x101A])
#define PMR_TMR2_OSC     (PM_RAM[0x101B])
#define PMR_TMR3_SCALE   (PM_RAM[0x101C])
#define PMR_TMR3_OSC     (PM_RAM[0x101D])
#define PMR_IRQ_PRI1     (PM_RAM[0x1020])
#define PMR_IRQ_PRI2     (PM_RAM[0x1021])
#define PMR_IRQ_PRI3     (PM_RAM[0x1022])
#define PMR_IRQ_ENA1     (PM_RAM[0x1023])
#define PMR_IRQ_ENA2     (PM_RAM[0x1024])
#define PMR_IRQ_ENA3     (PM_RAM[0x1025])
#define PMR_IRQ_ENA4     (PM_RAM[0x1026])
#define PMR_IRQ_ACT1     (PM_RAM[0x1027])
#define PMR_IRQ_ACT2     (PM_RAM[0x1028])
#define PMR_IRQ_ACT3     (PM_RAM[0x1029])
#define PMR_IRQ_ACT4     (PM_RAM[0x102A])
#define PMR_TMR1_CTRL_L  (PM_RAM[0x1030])
#define PMR_TMR1_CTRL_H  (PM_RAM[0x1031])
#define PMR_TMR1_PVT_L   (PM_RAM[0x1034])
#define PMR_TMR1_PVT_H   (PM_RAM[0x1035])
#define PMR_TMR2_CTRL_L  (PM_RAM[0x1038])
#define PMR_TMR2_CTRL_H  (PM_RAM[0x1039])
#define PMR_TMR2_PVT_L   (PM_RAM[0x103C])
#define PMR_TMR2_PVT_H   (PM_RAM[0x103D])
#define PMR_TMR256_CTRL  (PM_RAM[0x1040])
#define PMR_REG_44       (PM_RAM[0x1044])
#define PMR_REG_45       (PM_RAM[0x1045])
#define PMR_REG_46       (PM_RAM[0x1046])
#define PMR_REG_47       (PM_RAM[0x1047])
#define PMR_TMR3_CTRL_L  (PM_RAM[0x1048])
#define PMR_TMR3_CTRL_H  (PM_RAM[0x1049])
#define PMR_REG_50       (PM_RAM[0x1050])
#define PMR_REG_51       (PM_RAM[0x1051])
#define PMR_KEY_PAD      (PM_RAM[0x1052])
#define PMR_REG_53       (PM_RAM[0x1053])
#define PMR_REG_54       (PM_RAM[0x1054])
#define PMR_REG_55       (PM_RAM[0x1055])
#define PMR_IO_DIR       (PM_RAM[0x1060])
#define PMR_IO_DATA      (PM_RAM[0x1061])
#define PMR_REG_62       (PM_RAM[0x1062])
#define PMR_AUD_CTRL     (PM_RAM[0x1070])
#define PMR_AUD_VOL      (PM_RAM[0x1071])
#define PMR_PRC_MODE     (PM_RAM[0x1080])
#define PMR_PRC_RATE     (PM_RAM[0x1081])
#define PMR_PRC_MAP_LO   (PM_RAM[0x1082])
#define PMR_PRC_MAP_MID  (PM_RAM[0x1083])
#define PMR_PRC_MAP_HI   (PM_RAM[0x1084])
#define PMR_PRC_SCROLL_Y (PM_RAM[0x1085])
#define PMR_PRC_SCROLL_X (PM_RAM[0x1086])
#define PMR_PRC_SPR_LO   (PM_RAM[0x1087])
#define PMR_PRC_SPR_MID  (PM_RAM[0x1088])
#define PMR_PRC_SPR_HI   (PM_RAM[0x1089])

static const uint8_t PM_IO_INIT[256] = {
    0x7F,0x20,0x5C,0xff,0xff,0xff,0xff,0xff, 0x01,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
    0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
    0x00,0x30,0x02,0x00,0x02,0x00,0x00,0x40, 0x00,0xC0,0x40,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0xFF,0xFF,0x00,0x00,0xFF,0xFF, 0x00,0x00,0xFF,0xFF,0x00,0x00,0xFF,0xFF,
    0x00,0x00,0xff,0xff,0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0xFF,0x00,0x00,0xFF,0xFF,
    0xFF,0x00,0xFF,0x00,0x01,0x01,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x32,0x64,0x00,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff,0xff,0xff,0x40,0xFF
};

static uint32_t PM_ROM_Size, PM_ROM_Mask;
static int PokeHWCycles;
static int PokeMini_FrameDone;
static int StallCPU;
static int MinxIRQ_MasterIRQ;
static int PokeMini_EEPROMWritten;
static int PokeMini_Rumbling;
static int PokeMini_ShockKey;
static uint8_t prev_keys_mask;
static uint8_t using_freebios;
static char pm_info_str[96];

/* Audio state */
static uint32_t pm_snd_hz;
static uint32_t pm_snd_inc;
static int32_t  pm_aud_ccnt;
static int16_t  pm_aud_vol, pm_pwm_mul;
static int32_t  pm_hp[4], pm_lp[4];
static uint32_t pm_snd_rd, pm_snd_wr;

static int MinxCPU_CallIRQ(uint8_t addr)
{
    if (MinxCPU.Status == MINX_STATUS_IRQ) return 0;
    MinxCPU.Status = MINX_STATUS_IRQ;
    MinxCPU.IRQ_Vector = addr;
    return 1;
}

static void MinxIRQ_Process(void)
{
    if (!MinxIRQ_MasterIRQ) return;
    if (PMR_IRQ_PRI1 & 0xC0) {
        if ((PMR_IRQ_ENA1 & 0x80) && (PMR_IRQ_ACT1 & 0x80)) { MinxCPU_CallIRQ(0x03 << 1); return; }
        if ((PMR_IRQ_ENA1 & 0x40) && (PMR_IRQ_ACT1 & 0x40)) { MinxCPU_CallIRQ(0x04 << 1); return; }
    }
    if (PMR_IRQ_PRI1 & 0x30) {
        if ((PMR_IRQ_ENA1 & 0x20) && (PMR_IRQ_ACT1 & 0x20)) { MinxCPU_CallIRQ(0x05 << 1); return; }
        if ((PMR_IRQ_ENA1 & 0x10) && (PMR_IRQ_ACT1 & 0x10)) { MinxCPU_CallIRQ(0x06 << 1); return; }
    }
    if (PMR_IRQ_PRI1 & 0x0C) {
        if ((PMR_IRQ_ENA1 & 0x08) && (PMR_IRQ_ACT1 & 0x08)) { MinxCPU_CallIRQ(0x07 << 1); return; }
        if ((PMR_IRQ_ENA1 & 0x04) && (PMR_IRQ_ACT1 & 0x04)) { MinxCPU_CallIRQ(0x08 << 1); return; }
    }
    if (PMR_IRQ_PRI1 & 0x03) {
        if ((PMR_IRQ_ENA1 & 0x02) && (PMR_IRQ_ACT1 & 0x02)) { MinxCPU_CallIRQ(0x09 << 1); return; }
        if ((PMR_IRQ_ENA1 & 0x01) && (PMR_IRQ_ACT1 & 0x01)) { MinxCPU_CallIRQ(0x0A << 1); return; }
    }
    if (PMR_IRQ_PRI2 & 0xC0) {
        if ((PMR_IRQ_ENA2 & 0x20) && (PMR_IRQ_ACT2 & 0x20)) { MinxCPU_CallIRQ(0x0B << 1); return; }
        if ((PMR_IRQ_ENA2 & 0x10) && (PMR_IRQ_ACT2 & 0x10)) { MinxCPU_CallIRQ(0x0C << 1); return; }
        if ((PMR_IRQ_ENA2 & 0x08) && (PMR_IRQ_ACT2 & 0x08)) { MinxCPU_CallIRQ(0x0D << 1); return; }
        if ((PMR_IRQ_ENA2 & 0x04) && (PMR_IRQ_ACT2 & 0x04)) { MinxCPU_CallIRQ(0x0E << 1); return; }
    }
    if (PMR_IRQ_PRI3 & 0x03) {
        if ((PMR_IRQ_ENA4 & 0x80) && (PMR_IRQ_ACT4 & 0x80)) { MinxCPU_CallIRQ(0x0F << 1); return; }
        if ((PMR_IRQ_ENA4 & 0x40) && (PMR_IRQ_ACT4 & 0x40)) { MinxCPU_CallIRQ(0x10 << 1); return; }
    }
    if (PMR_IRQ_PRI2 & 0x30) {
        if ((PMR_IRQ_ENA2 & 0x02) && (PMR_IRQ_ACT2 & 0x02)) { MinxCPU_CallIRQ(0x13 << 1); return; }
        if ((PMR_IRQ_ENA2 & 0x01) && (PMR_IRQ_ACT2 & 0x01)) { MinxCPU_CallIRQ(0x14 << 1); return; }
    }
    if (PMR_IRQ_PRI2 & 0x0C) {
        if ((PMR_IRQ_ENA3 & 0x80) && (PMR_IRQ_ACT3 & 0x80)) { MinxCPU_CallIRQ(0x15 << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x40) && (PMR_IRQ_ACT3 & 0x40)) { MinxCPU_CallIRQ(0x16 << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x20) && (PMR_IRQ_ACT3 & 0x20)) { MinxCPU_CallIRQ(0x17 << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x10) && (PMR_IRQ_ACT3 & 0x10)) { MinxCPU_CallIRQ(0x18 << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x08) && (PMR_IRQ_ACT3 & 0x08)) { MinxCPU_CallIRQ(0x19 << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x04) && (PMR_IRQ_ACT3 & 0x04)) { MinxCPU_CallIRQ(0x1A << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x02) && (PMR_IRQ_ACT3 & 0x02)) { MinxCPU_CallIRQ(0x1B << 1); return; }
        if ((PMR_IRQ_ENA3 & 0x01) && (PMR_IRQ_ACT3 & 0x01)) { MinxCPU_CallIRQ(0x1C << 1); return; }
    }
    if (PMR_IRQ_PRI2 & 0x03) {
        if ((PMR_IRQ_ENA4 & 0x04) && (PMR_IRQ_ACT4 & 0x04)) { MinxCPU_CallIRQ(0x1D << 1); return; }
        if ((PMR_IRQ_ENA4 & 0x02) && (PMR_IRQ_ACT4 & 0x02)) { MinxCPU_CallIRQ(0x1E << 1); return; }
        if ((PMR_IRQ_ENA4 & 0x01) && (PMR_IRQ_ACT4 & 0x01)) { MinxCPU_CallIRQ(0x1F << 1); return; }
    }
}

static void MinxCPU_OnIRQAct(uint8_t intr)
{
    switch (intr) {
    case 0x03: PMR_IRQ_ACT1 |= 0x80; break;
    case 0x04: PMR_IRQ_ACT1 |= 0x40; break;
    case 0x05: PMR_IRQ_ACT1 |= 0x20; break;
    case 0x06: PMR_IRQ_ACT1 |= 0x10; break;
    case 0x07: PMR_IRQ_ACT1 |= 0x08; break;
    case 0x08: PMR_IRQ_ACT1 |= 0x04; break;
    case 0x09: PMR_IRQ_ACT1 |= 0x02; break;
    case 0x0A: PMR_IRQ_ACT1 |= 0x01; break;
    case 0x0B: PMR_IRQ_ACT2 |= 0x20; break;
    case 0x0C: PMR_IRQ_ACT2 |= 0x10; break;
    case 0x0D: PMR_IRQ_ACT2 |= 0x08; break;
    case 0x0E: PMR_IRQ_ACT2 |= 0x04; break;
    case 0x0F: PMR_IRQ_ACT4 |= 0x80; break;
    case 0x10: PMR_IRQ_ACT4 |= 0x40; break;
    case 0x13: PMR_IRQ_ACT2 |= 0x02; break;
    case 0x14: PMR_IRQ_ACT2 |= 0x01; break;
    case 0x15: PMR_IRQ_ACT3 |= 0x80; break;
    case 0x16: PMR_IRQ_ACT3 |= 0x40; break;
    case 0x17: PMR_IRQ_ACT3 |= 0x20; break;
    case 0x18: PMR_IRQ_ACT3 |= 0x10; break;
    case 0x19: PMR_IRQ_ACT3 |= 0x08; break;
    case 0x1A: PMR_IRQ_ACT3 |= 0x04; break;
    case 0x1B: PMR_IRQ_ACT3 |= 0x02; break;
    case 0x1C: PMR_IRQ_ACT3 |= 0x01; break;
    }
    MinxIRQ_Process();
}

static void MinxCPU_OnIRQHandle(uint8_t cpuflag, uint8_t shift_u)
{
    if (shift_u || (cpuflag & 0xC0) == 0xC0) {
        MinxIRQ_MasterIRQ = 0;
    } else {
        MinxIRQ_MasterIRQ = 1;
        MinxIRQ_Process();
    }
}

static uint8_t MinxIRQ_ReadReg(uint8_t reg)
{
    switch (reg) {
    case 0x20: return PMR_IRQ_PRI1;
    case 0x21: return PMR_IRQ_PRI2;
    case 0x22: return PMR_IRQ_PRI3 & 0x03;
    case 0x23: return PMR_IRQ_ENA1;
    case 0x24: return PMR_IRQ_ENA2 & 0x3F;
    case 0x25: return PMR_IRQ_ENA3;
    case 0x26: return PMR_IRQ_ENA4 & 0xF7;
    case 0x27: return PMR_IRQ_ACT1;
    case 0x28: return PMR_IRQ_ACT2 & 0x3F;
    case 0x29: return PMR_IRQ_ACT3;
    case 0x2A: return PMR_IRQ_ACT4 & 0xF7;
    }
    return 0;
}

static void MinxIRQ_WriteReg(int cpu, uint8_t reg, uint8_t val)
{
    switch (reg) {
    case 0x20: PMR_IRQ_PRI1 = val; MinxIRQ_Process(); break;
    case 0x21: PMR_IRQ_PRI2 = val; MinxIRQ_Process(); break;
    case 0x22: PMR_IRQ_PRI3 = val; MinxIRQ_Process(); break;
    case 0x23: PMR_IRQ_ENA1 = val; MinxIRQ_Process(); break;
    case 0x24: PMR_IRQ_ENA2 = val & 0x3F; MinxIRQ_Process(); break;
    case 0x25: PMR_IRQ_ENA3 = val; MinxIRQ_Process(); break;
    case 0x26: PMR_IRQ_ENA4 = val & 0xF7; MinxIRQ_Process(); break;
    case 0x27: if (cpu) PMR_IRQ_ACT1 &= ~val; else PMR_IRQ_ACT1 = val; break;
    case 0x28: if (cpu) PMR_IRQ_ACT2 &= ~val; else PMR_IRQ_ACT2 = val & 0x3F; break;
    case 0x29: if (cpu) PMR_IRQ_ACT3 &= ~val; else PMR_IRQ_ACT3 = val; break;
    case 0x2A: if (cpu) PMR_IRQ_ACT4 &= ~val; else PMR_IRQ_ACT4 = val & 0xF7; break;
    }
}

typedef union { struct { uint8_t L, H; } B; uint16_t W; } MinxWord;
static struct {
    uint32_t SecTimerCnt;
    int32_t TmrSecs;
    uint32_t Tmr1DecA, Tmr1DecB, Tmr1CntA, Tmr1CntB, Tmr1PreA, Tmr1PreB;
    uint32_t Tmr2DecA, Tmr2DecB, Tmr2CntA, Tmr2CntB, Tmr2PreA, Tmr2PreB;
    uint32_t Tmr3DecA, Tmr3DecB, Tmr3CntA, Tmr3CntB, Tmr3PreA, Tmr3PreB;
    uint32_t Tmr8Cnt;
    MinxWord Tmr3Cnt16;
    uint16_t Timer3Piv;
    uint8_t TmrXEna2, TmrXEna1;
    int Tmr1WMode, Tmr1LEna, Tmr1HEna;
    int Tmr2WMode, Tmr2LEna, Tmr2HEna;
    int Tmr3WMode, Tmr3LEna, Tmr3HEna;
} MinxTimers;

static const uint32_t TmrDecOsc1[16] = {
    0,0,0,0,0,0,0,0,
    (16777216/2),(16777216/8),(16777216/32),(16777216/64),
    (16777216/128),(16777216/256),(16777216/1024),(16777216/4096)
};
static const uint32_t TmrDecOsc2[16] = {
    0,0,0,0,0,0,0,0,
    (16777216/122),(16777216/244),(16777216/488),(16777216/977),
    (16777216/1953),(16777216/3906),(16777216/7812),(16777216/15625)
};

static void TmrUpdateScalars(void)
{
    MinxTimers.Tmr1DecA = (PMR_TMR1_ENA_OSC & 1) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[PMR_TMR1_SCALE & 15] : 0)
                                                 : (MinxTimers.TmrXEna1 ? TmrDecOsc1[PMR_TMR1_SCALE & 15] : 0);
    MinxTimers.Tmr1DecB = (PMR_TMR1_ENA_OSC & 2) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[(PMR_TMR1_SCALE >> 4) & 15] : 0)
                                                 : (MinxTimers.TmrXEna1 ? TmrDecOsc1[(PMR_TMR1_SCALE >> 4) & 15] : 0);
    MinxTimers.Tmr2DecA = (PMR_TMR2_OSC & 1) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[PMR_TMR2_SCALE & 15] : 0)
                                             : (MinxTimers.TmrXEna1 ? TmrDecOsc1[PMR_TMR2_SCALE & 15] : 0);
    MinxTimers.Tmr2DecB = (PMR_TMR2_OSC & 2) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[(PMR_TMR2_SCALE >> 4) & 15] : 0)
                                             : (MinxTimers.TmrXEna1 ? TmrDecOsc1[(PMR_TMR2_SCALE >> 4) & 15] : 0);
    MinxTimers.Tmr3DecA = (PMR_TMR3_OSC & 1) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[PMR_TMR3_SCALE & 15] : 0)
                                             : (MinxTimers.TmrXEna1 ? TmrDecOsc1[PMR_TMR3_SCALE & 15] : 0);
    MinxTimers.Tmr3DecB = (PMR_TMR3_OSC & 2) ? (MinxTimers.TmrXEna2 ? TmrDecOsc2[(PMR_TMR3_SCALE >> 4) & 15] : 0)
                                             : (MinxTimers.TmrXEna1 ? TmrDecOsc1[(PMR_TMR3_SCALE >> 4) & 15] : 0);
}

static void MinxTimers_Sync(void)
{
    uint32_t PreCount;
    if (PMR_TMR256_CTRL) {
        PreCount = MinxTimers.Tmr8Cnt;
        MinxTimers.Tmr8Cnt += (uint32_t)(16777216 / 15625) * (uint32_t)PokeHWCycles;
        if ((PreCount & 0x08000000u) ^ (MinxTimers.Tmr8Cnt & 0x08000000u)) MinxCPU_OnIRQAct(0x0B);
        if ((PreCount & 0x20000000u) ^ (MinxTimers.Tmr8Cnt & 0x20000000u)) MinxCPU_OnIRQAct(0x0C);
        if ((PreCount & 0x80000000u) ^ (MinxTimers.Tmr8Cnt & 0x80000000u)) MinxCPU_OnIRQAct(0x0D);
        if (PreCount > MinxTimers.Tmr8Cnt) MinxCPU_OnIRQAct(0x0E);
    }
    if (PMR_SEC_CTRL) {
        MinxTimers.TmrSecs += PokeHWCycles;
        if (MinxTimers.TmrSecs >= 4000000) {
            MinxTimers.SecTimerCnt++;
            MinxTimers.TmrSecs -= 4000000;
        }
    }
    if (MinxTimers.Tmr1WMode) {
        if (MinxTimers.Tmr1LEna) {
            PreCount = MinxTimers.Tmr1CntA;
            MinxTimers.Tmr1CntA -= MinxTimers.Tmr1DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr1CntA) {
                PreCount = MinxTimers.Tmr1CntB;
                MinxTimers.Tmr1CntB -= 0x01000000u;
                if (PreCount < MinxTimers.Tmr1CntB) {
                    MinxTimers.Tmr1CntA = MinxTimers.Tmr1PreA;
                    MinxTimers.Tmr1CntB = MinxTimers.Tmr1PreB;
                    MinxCPU_OnIRQAct(0x07);
                }
            }
        }
    } else {
        if (MinxTimers.Tmr1LEna) {
            PreCount = MinxTimers.Tmr1CntA;
            MinxTimers.Tmr1CntA -= MinxTimers.Tmr1DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr1CntA) { MinxTimers.Tmr1CntA = MinxTimers.Tmr1PreA; MinxCPU_OnIRQAct(0x08); }
        }
        if (MinxTimers.Tmr1HEna) {
            PreCount = MinxTimers.Tmr1CntB;
            MinxTimers.Tmr1CntB -= MinxTimers.Tmr1DecB * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr1CntB) { MinxTimers.Tmr1CntB = MinxTimers.Tmr1PreB; MinxCPU_OnIRQAct(0x07); }
        }
    }
    if (MinxTimers.Tmr2WMode) {
        if (MinxTimers.Tmr2LEna) {
            PreCount = MinxTimers.Tmr2CntA;
            MinxTimers.Tmr2CntA -= MinxTimers.Tmr2DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr2CntA) {
                PreCount = MinxTimers.Tmr2CntB;
                MinxTimers.Tmr2CntB -= 0x01000000u;
                if (PreCount < MinxTimers.Tmr2CntB) {
                    MinxTimers.Tmr2CntA = MinxTimers.Tmr2PreA;
                    MinxTimers.Tmr2CntB = MinxTimers.Tmr2PreB;
                    MinxCPU_OnIRQAct(0x05);
                }
            }
        }
    } else {
        if (MinxTimers.Tmr2LEna) {
            PreCount = MinxTimers.Tmr2CntA;
            MinxTimers.Tmr2CntA -= MinxTimers.Tmr2DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr2CntA) { MinxTimers.Tmr2CntA = MinxTimers.Tmr2PreA; MinxCPU_OnIRQAct(0x06); }
        }
        if (MinxTimers.Tmr2HEna) {
            PreCount = MinxTimers.Tmr2CntB;
            MinxTimers.Tmr2CntB -= MinxTimers.Tmr2DecB * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr2CntB) { MinxTimers.Tmr2CntB = MinxTimers.Tmr2PreB; MinxCPU_OnIRQAct(0x05); }
        }
    }
    if (MinxTimers.Tmr3WMode) {
        if (MinxTimers.Tmr3LEna) {
            PreCount = MinxTimers.Tmr3CntA;
            MinxTimers.Tmr3CntA -= MinxTimers.Tmr3DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr3CntA) {
                PreCount = MinxTimers.Tmr3CntB;
                MinxTimers.Tmr3CntB -= 0x01000000u;
                if (PreCount < MinxTimers.Tmr3CntB) {
                    MinxTimers.Tmr3CntA = MinxTimers.Tmr3PreA;
                    MinxTimers.Tmr3CntB = MinxTimers.Tmr3PreB;
                    MinxCPU_OnIRQAct(0x09);
                }
                MinxTimers.Tmr3Cnt16.B.H = (uint8_t)(MinxTimers.Tmr3CntB >> 24);
            }
            PreCount = MinxTimers.Tmr3Cnt16.W;
            MinxTimers.Tmr3Cnt16.B.L = (uint8_t)(MinxTimers.Tmr3CntA >> 24);
            if ((PreCount > MinxTimers.Timer3Piv) && (MinxTimers.Tmr3Cnt16.W <= MinxTimers.Timer3Piv))
                MinxCPU_OnIRQAct(0x0A);
        }
    } else {
        if (MinxTimers.Tmr3LEna) {
            PreCount = MinxTimers.Tmr3CntA;
            MinxTimers.Tmr3CntA -= MinxTimers.Tmr3DecA * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr3CntA) MinxTimers.Tmr3CntA = MinxTimers.Tmr3PreA;
            MinxTimers.Tmr3Cnt16.B.L = (uint8_t)(MinxTimers.Tmr3CntA >> 24);
        }
        if (MinxTimers.Tmr3HEna) {
            PreCount = MinxTimers.Tmr3CntB;
            MinxTimers.Tmr3CntB -= MinxTimers.Tmr3DecB * (uint32_t)PokeHWCycles;
            if (PreCount < MinxTimers.Tmr3CntB) { MinxTimers.Tmr3CntB = MinxTimers.Tmr3PreB; MinxCPU_OnIRQAct(0x09); }
            PreCount = MinxTimers.Tmr3Cnt16.W;
            MinxTimers.Tmr3Cnt16.B.H = (uint8_t)(MinxTimers.Tmr3CntB >> 24);
            if ((PreCount > MinxTimers.Timer3Piv) && (MinxTimers.Tmr3Cnt16.W <= MinxTimers.Timer3Piv))
                MinxCPU_OnIRQAct(0x0A);
        }
    }
}

static uint8_t MinxTimers_ReadReg(uint8_t reg)
{
    switch (reg) {
    case 0x08: return PMR_SEC_CTRL & 0x01;
    case 0x09: return (uint8_t)MinxTimers.SecTimerCnt;
    case 0x0A: return (uint8_t)(MinxTimers.SecTimerCnt >> 8);
    case 0x0B: return (uint8_t)(MinxTimers.SecTimerCnt >> 16);
    case 0x18: return PMR_TMR1_SCALE;
    case 0x19: return PMR_TMR1_ENA_OSC & 0x33;
    case 0x1A: return PMR_TMR2_SCALE;
    case 0x1B: return PMR_TMR2_OSC & 0x03;
    case 0x1C: return PMR_TMR3_SCALE;
    case 0x1D: return PMR_TMR3_OSC & 0x03;
    case 0x30: return (PMR_TMR1_CTRL_L & 0x80) ? (PMR_TMR1_CTRL_L & 0x85) : (PMR_TMR1_CTRL_L & 0x0D);
    case 0x31: return (PMR_TMR1_CTRL_L & 0x80) ? (PMR_TMR1_CTRL_H & 0x08) : (PMR_TMR1_CTRL_H & 0x0D);
    case 0x32: return (uint8_t)(MinxTimers.Tmr1PreA >> 24);
    case 0x33: return (uint8_t)(MinxTimers.Tmr1PreB >> 24);
    case 0x34: return PMR_TMR1_PVT_L;
    case 0x35: return PMR_TMR1_PVT_H;
    case 0x36: return (uint8_t)(MinxTimers.Tmr1CntA >> 24);
    case 0x37: return (uint8_t)(MinxTimers.Tmr1CntB >> 24);
    case 0x38: return (PMR_TMR2_CTRL_L & 0x80) ? (PMR_TMR2_CTRL_L & 0x85) : (PMR_TMR2_CTRL_L & 0x0D);
    case 0x39: return (PMR_TMR2_CTRL_L & 0x80) ? (PMR_TMR2_CTRL_H & 0x08) : (PMR_TMR2_CTRL_H & 0x0D);
    case 0x3A: return (uint8_t)(MinxTimers.Tmr2PreA >> 24);
    case 0x3B: return (uint8_t)(MinxTimers.Tmr2PreB >> 24);
    case 0x3C: return PMR_TMR2_PVT_L;
    case 0x3D: return PMR_TMR2_PVT_H;
    case 0x3E: return (uint8_t)(MinxTimers.Tmr2CntA >> 24);
    case 0x3F: return (uint8_t)(MinxTimers.Tmr2CntB >> 24);
    case 0x40: return PMR_TMR256_CTRL;
    case 0x41: return (uint8_t)(MinxTimers.Tmr8Cnt >> 24);
    case 0x48: return (PMR_TMR3_CTRL_L & 0x80) ? (PMR_TMR3_CTRL_L & 0x85) : (PMR_TMR3_CTRL_L & 0x0D);
    case 0x49: return (PMR_TMR3_CTRL_L & 0x80) ? (PMR_TMR3_CTRL_H & 0x08) : (PMR_TMR3_CTRL_H & 0x0D);
    case 0x4A: return (uint8_t)(MinxTimers.Tmr3PreA >> 24);
    case 0x4B: return (uint8_t)(MinxTimers.Tmr3PreB >> 24);
    case 0x4C: return (uint8_t)MinxTimers.Timer3Piv;
    case 0x4D: return (uint8_t)(MinxTimers.Timer3Piv >> 8);
    case 0x4E: return (uint8_t)(MinxTimers.Tmr3CntA >> 24);
    case 0x4F: return (uint8_t)(MinxTimers.Tmr3CntB >> 24);
    }
    return reg;
}

static void MinxTimers_WriteReg(uint8_t reg, uint8_t val)
{
    switch (reg) {
    case 0x08: if (val & 2) MinxTimers.SecTimerCnt = 0; PMR_SEC_CTRL = val & 1; break;
    case 0x18: PMR_TMR1_SCALE = val; TmrUpdateScalars(); break;
    case 0x19: PMR_TMR1_ENA_OSC = val & 0x33; MinxTimers.TmrXEna2 = val & 0x10; MinxTimers.TmrXEna1 = val & 0x20; TmrUpdateScalars(); break;
    case 0x1A: PMR_TMR2_SCALE = val; TmrUpdateScalars(); break;
    case 0x1B: PMR_TMR2_OSC = val & 3; TmrUpdateScalars(); break;
    case 0x1C: PMR_TMR3_SCALE = val; TmrUpdateScalars(); break;
    case 0x1D: PMR_TMR3_OSC = val & 3; TmrUpdateScalars(); break;
    case 0x30:
        PMR_TMR1_CTRL_L = val & 0x8D; MinxTimers.Tmr1LEna = val & 4;
        MinxTimers.Tmr1WMode = (val & 0x80) ? 1 : 0;
        if (val & 2) { MinxTimers.Tmr1CntA = MinxTimers.Tmr1PreA; if (MinxTimers.Tmr1WMode) MinxTimers.Tmr1CntB = MinxTimers.Tmr1PreB; }
        break;
    case 0x31:
        PMR_TMR1_CTRL_H = val & 0x0D; MinxTimers.Tmr1HEna = val & 4;
        if (!(PMR_TMR1_CTRL_L & 0x80) && (val & 2)) MinxTimers.Tmr1CntB = MinxTimers.Tmr1PreB;
        break;
    case 0x32: MinxTimers.Tmr1PreA = (uint32_t)val << 24; break;
    case 0x33: MinxTimers.Tmr1PreB = (uint32_t)val << 24; break;
    case 0x34: PMR_TMR1_PVT_L = val; break;
    case 0x35: PMR_TMR1_PVT_H = val; break;
    case 0x38:
        PMR_TMR2_CTRL_L = val & 0x8D; MinxTimers.Tmr2LEna = val & 4;
        MinxTimers.Tmr2WMode = (val & 0x80) ? 1 : 0;
        if (val & 2) { MinxTimers.Tmr2CntA = MinxTimers.Tmr2PreA; if (MinxTimers.Tmr2WMode) MinxTimers.Tmr2CntB = MinxTimers.Tmr2PreB; }
        break;
    case 0x39:
        PMR_TMR2_CTRL_H = val & 0x0D; MinxTimers.Tmr2HEna = val & 4;
        if (!(PMR_TMR2_CTRL_L & 0x80) && (val & 2)) MinxTimers.Tmr2CntB = MinxTimers.Tmr2PreB;
        break;
    case 0x3A: MinxTimers.Tmr2PreA = (uint32_t)val << 24; break;
    case 0x3B: MinxTimers.Tmr2PreB = (uint32_t)val << 24; break;
    case 0x3C: PMR_TMR2_PVT_L = val; break;
    case 0x3D: PMR_TMR2_PVT_H = val; break;
    case 0x40: PMR_TMR256_CTRL = val & 1; if (val & 2) MinxTimers.Tmr8Cnt = 0; break;
    case 0x48:
        PMR_TMR3_CTRL_L = val & 0x8D; MinxTimers.Tmr3LEna = val & 4;
        MinxTimers.Tmr3WMode = (val & 0x80) ? 1 : 0;
        if (val & 2) { MinxTimers.Tmr3CntA = MinxTimers.Tmr3PreA; if (MinxTimers.Tmr3WMode) MinxTimers.Tmr3CntB = MinxTimers.Tmr3PreB; }
        break;
    case 0x49:
        PMR_TMR3_CTRL_H = val & 0x0D; MinxTimers.Tmr3HEna = val & 4;
        if (!(PMR_TMR3_CTRL_L & 0x80) && (val & 2)) MinxTimers.Tmr3CntB = MinxTimers.Tmr3PreB;
        break;
    case 0x4A: MinxTimers.Tmr3PreA = (uint32_t)val << 24; break;
    case 0x4B: MinxTimers.Tmr3PreB = (uint32_t)val << 24; break;
    case 0x4C: MinxTimers.Timer3Piv = (MinxTimers.Timer3Piv & 0xFF00u) | val; break;
    case 0x4D: MinxTimers.Timer3Piv = (MinxTimers.Timer3Piv & 0x00FFu) | ((uint16_t)val << 8); break;
    }
}

static struct {
    uint8_t EEPLastPins, ListenState, OperState, EEPData;
    int32_t EEPBit;
    uint16_t EEPAddress;
} MinxIO;

enum { EEP_IDLE = 0, EEP_LISTEN = 1 };
enum { EEP_DEV = 0, EEP_AHI = 1, EEP_ALO = 2, EEP_WB = 3, EEP_RB = 4 };

static void MinxIO_EEPWriteByte(uint8_t data)
{
    switch (MinxIO.OperState) {
    case EEP_DEV:
        if ((data & 0xF0) == 0xA0)
            MinxIO.OperState = (data & 1) ? EEP_RB : EEP_AHI;
        break;
    case EEP_AHI:
        MinxIO.EEPAddress = (MinxIO.EEPAddress & 0x00FFu) | ((uint16_t)data << 8);
        MinxIO.OperState = EEP_ALO;
        break;
    case EEP_ALO:
        MinxIO.EEPAddress = (MinxIO.EEPAddress & 0xFF00u) | data;
        MinxIO.OperState = EEP_WB;
        break;
    case EEP_WB:
        PokeMini_EEPROMWritten = 1;
        EEPROM[MinxIO.EEPAddress & 0x1FFFu] = data;
        MinxIO.EEPAddress++;
        break;
    case EEP_RB:
        MinxIO.EEPAddress++;
        break;
    }
}

static void MinxIO_EEPWEvent(uint8_t bits)
{
    uint8_t rise = bits & ~MinxIO.EEPLastPins;
    uint8_t fall = ~bits & MinxIO.EEPLastPins;
    MinxIO.EEPLastPins = bits;

    if ((fall & 0x04) && (bits & 0x08)) {
        MinxIO.ListenState = EEP_LISTEN;
        MinxIO.OperState = EEP_DEV;
        MinxIO.EEPBit = 8;
        MinxIO.EEPData = 0;
        return;
    }
    if ((rise & 0x04) && (bits & 0x08)) {
        MinxIO.ListenState = EEP_IDLE;
        return;
    }
    if (MinxIO.ListenState == EEP_IDLE) return;
    if (rise & 0x08) {
        int dat = (bits & 0x04) ? 1 : 0;
        if (MinxIO.EEPBit < 0) {
            MinxIO_EEPWriteByte(MinxIO.EEPData);
            MinxIO.EEPBit = 8;
            MinxIO.EEPData = 0;
        } else {
            MinxIO.EEPData = (uint8_t)((MinxIO.EEPData << 1) | dat);
        }
    } else if (fall & 0x08) {
        MinxIO.EEPBit--;
    }
}

static int MinxIO_EEPREvent(void)
{
    int valid = (MinxIO.EEPBit >= 0) && (MinxIO.EEPBit < 8);
    if (MinxIO.ListenState == EEP_IDLE) return 1;
    if (MinxIO.OperState == EEP_RB)
        return valid ? ((EEPROM[MinxIO.EEPAddress & 0x1FFFu] >> MinxIO.EEPBit) & 1) : 0;
    return valid;
}

static uint8_t MinxIO_ReadReg(uint8_t reg)
{
    switch (reg) {
    case 0x10: return PMR_SYS_BATT;
    case 0x44: return PMR_REG_44;
    case 0x45: return PMR_REG_45;
    case 0x46: return PMR_REG_46;
    case 0x47: return PMR_REG_47;
    case 0x50: return PMR_REG_50;
    case 0x51: return PMR_REG_51;
    case 0x52: return PMR_KEY_PAD;
    case 0x53: return PMR_REG_53;
    case 0x54: return PMR_REG_54;
    case 0x55: return PMR_REG_55;
    case 0x60: return PMR_IO_DIR;
    case 0x61: {
        uint8_t inp = MinxIO_EEPREvent() ? 0x04 : 0;
        return (PMR_IO_DATA & PMR_IO_DIR) | (inp & ~PMR_IO_DIR);
    }
    case 0x62: return PMR_REG_62;
    }
    return 0;
}

static void MinxIO_WriteReg(uint8_t reg, uint8_t val)
{
    switch (reg) {
    case 0x10: PMR_SYS_BATT = (PMR_SYS_BATT & 0x20) | (val & 0x1F); break;
    case 0x44: PMR_REG_44 = val & 0xF7; break;
    case 0x45: PMR_REG_45 = val & 0x0F; break;
    case 0x46: PMR_REG_46 = val; break;
    case 0x47: PMR_REG_47 = val & 0x0F; break;
    case 0x50: PMR_REG_50 = val; break;
    case 0x51: PMR_REG_51 = val & 0x03; break;
    case 0x53: PMR_REG_53 = 0x00;
    case 0x54: PMR_REG_54 = val & 0x77;
    case 0x55: PMR_REG_55 = val & 0x07;
    case 0x60:
        PMR_IO_DIR = val;
        { uint8_t out = (0x40 & ~PMR_IO_DIR) | (PMR_IO_DATA & PMR_IO_DIR); PokeMini_Rumbling = out & 0x10; MinxIO_EEPWEvent(out); }
        break;
    case 0x61:
        PMR_IO_DATA = val;
        { uint8_t out = (0x40 & ~PMR_IO_DIR) | (PMR_IO_DATA & PMR_IO_DIR); PokeMini_Rumbling = out & 0x10; MinxIO_EEPWEvent(out); }
        break;
    case 0x62: PMR_REG_62 = val & 0xF0; break;
    }
}

static struct {
    int32_t Pixel0Intensity, Pixel1Intensity;
    uint8_t Column, StartLine, SetContrast, Contrast, SegmentDir, MaxContrast;
    uint8_t SetAllPix, InvAllPix, DisplayOn, Page, RowOrder, ReadModifyMode, RequireDummyR, RMWColumn;
    uint8_t LastRead;
} MinxLCD;
static int LCDDirty;

static const uint8_t ContrastLvl[64][2] = {
    {0,4},{0,4},{0,4},{0,4},{0,6},{0,11},{0,17},{0,24},{0,31},{0,40},{0,48},{0,57},{0,67},{0,77},{0,88},{0,99},
    {0,110},{0,122},{0,133},{0,146},{0,158},{0,171},{0,184},{0,198},{0,212},{0,226},{0,240},{0,255},{2,255},{5,255},{10,255},{15,255},
    {21,255},{27,255},{34,255},{41,255},{48,255},{56,255},{64,255},{73,255},{81,255},{90,255},{100,255},{109,255},{119,255},{129,255},{139,255},{149,255},
    {160,255},{171,255},{182,255},{193,255},{204,255},{216,255},{228,255},{240,255},{240,255},{240,255},{240,255},{240,255},{240,255},{240,255},{240,255},{240,255}
};
static const uint8_t Bits4[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

static void MinxLCD_SetContrast(uint8_t v)
{
    MinxLCD.Contrast = v & 0x3F;
    if (MinxLCD.MaxContrast) { MinxLCD.Pixel0Intensity = 240; MinxLCD.Pixel1Intensity = 255; }
    else { MinxLCD.Pixel0Intensity = ContrastLvl[MinxLCD.Contrast][0]; MinxLCD.Pixel1Intensity = ContrastLvl[MinxLCD.Contrast][1]; }
    LCDDirty = 4;
}

static void MinxLCD_Render(void)
{
    if (MinxLCD.DisplayOn) {
        for (int yC = 0; yC < 64; yC++) {
            int yP = (yC + MinxLCD.StartLine) & 63;
            if (MinxLCD.RowOrder) yP = 63 - yP;
            for (int xC = 0; xC < 96; xC++) {
                uint8_t pix = (WS->lcd_data[((yP >> 3) * 256) + xC] >> (yP & 7)) & 1;
                WS->lcd_pix_d[(yC * 96) + xC] = (pix ^ MinxLCD.InvAllPix) | MinxLCD.SetAllPix;
            }
        }
    } else {
        pm_zero(WS->lcd_pix_d, 96 * 64);
    }
}

static void MinxLCD_DecayRefresh(void)
{
    for (int i = 0; i < 96 * 64; i++) {
        uint8_t sh = ((MinxLCD.DisplayOn && WS->lcd_pix_d[i]) ? 0x08u : 0x00u) | (WS->lcd_pix_s[i] >> 1);
        WS->lcd_pix_s[i] = sh;
        int lv = Bits4[sh & 15u];
        WS->lcd_pix_a[i] = (uint8_t)((MinxLCD.Pixel0Intensity * (4 - lv) + MinxLCD.Pixel1Intensity * lv) >> 2);
    }
}

static uint8_t MinxLCD_ReadReg(int cpu, uint8_t reg)
{
    if (reg == 0xFE) {
        if (MinxLCD.SetContrast) { MinxLCD.SetContrast = 0; MinxLCD_SetContrast(0x3F); return 0; }
        return 0x40 | (MinxLCD.DisplayOn ? 0x20 : 0x00);
    }
    if (reg == 0xFF) {
        if (MinxLCD.SetContrast) { MinxLCD.SetContrast = 0; MinxLCD_SetContrast(0x3F); MinxLCD.LastRead = 0; }
        else if (!MinxLCD.RequireDummyR && cpu) {
            int col = MinxLCD.SegmentDir ? (131 - MinxLCD.Column) : MinxLCD.Column;
            MinxLCD.LastRead = WS->lcd_data[(col & 255) + ((MinxLCD.Page & 15) * 256)];
            if (MinxLCD.Page >= 8) MinxLCD.LastRead &= 1;
            if (!MinxLCD.ReadModifyMode) {
                if (++MinxLCD.Column > 131) MinxLCD.Column = 131;
                MinxLCD.RequireDummyR = 1;
            }
        } else {
            MinxLCD.RequireDummyR = 0;
        }
        return MinxLCD.LastRead;
    }
    return 0;
}

static void MinxLCD_WriteReg(uint8_t reg, uint8_t data)
{
    if (reg == 0xFE) {
        if (MinxLCD.SetContrast) { MinxLCD.SetContrast = 0; MinxLCD_SetContrast(data & 0x3F); return; }
        if (data <= 0x0F) { if (!MinxLCD.ReadModifyMode) { MinxLCD.Column = (MinxLCD.Column & 0xF0) | (data & 0x0F); MinxLCD.RequireDummyR = 1; } }
        else if (data <= 0x1F) { if (!MinxLCD.ReadModifyMode) { MinxLCD.Column = (MinxLCD.Column & 0x0F) | ((data & 0x0F) << 4); MinxLCD.RequireDummyR = 1; } }
        else if (data >= 0x40 && data <= 0x7F) { MinxLCD.StartLine = data - 0x40; LCDDirty = 4; }
        else if (data == 0x81) { MinxLCD.SetContrast = 1; }
        else if (data == 0xA0 || data == 0xA1) { MinxLCD.SegmentDir = data & 1; LCDDirty = 4; }
        else if (data == 0xA2 || data == 0xA3) { MinxLCD.MaxContrast = data & 1; MinxLCD_SetContrast(MinxLCD.Contrast); }
        else if (data == 0xA4 || data == 0xA5) { MinxLCD.SetAllPix = data & 1; LCDDirty = 4; }
        else if (data == 0xA6 || data == 0xA7) { MinxLCD.InvAllPix = data & 1; LCDDirty = 4; }
        else if (data == 0xAE || data == 0xAF) { MinxLCD.DisplayOn = data & 1; LCDDirty = 4; }
        else if (data >= 0xB0 && data <= 0xB8) { MinxLCD.Page = data & 15; }
        else if (data >= 0xC0 && data <= 0xCF) { MinxLCD.RowOrder = (data >= 0xC8) ? 1 : 0; LCDDirty = 4; }
        else if (data == 0xE0) { MinxLCD.ReadModifyMode = 1; MinxLCD.RMWColumn = MinxLCD.Column; }
        else if (data == 0xE2) {
            pm_zero(&MinxLCD, sizeof(MinxLCD));
            MinxLCD.LastRead = 0x40; MinxLCD.RequireDummyR = 1; MinxLCD_SetContrast(0x20);
        } else if (data == 0xEE) { MinxLCD.ReadModifyMode = 0; MinxLCD.Column = MinxLCD.RMWColumn; }
        return;
    }
    if (reg == 0xFF) {
        if (MinxLCD.SetContrast) { MinxLCD.SetContrast = 0; MinxLCD_SetContrast(data & 0x3F); }
        else {
            int col = MinxLCD.SegmentDir ? (131 - MinxLCD.Column) : MinxLCD.Column;
            WS->lcd_data[(col & 255) + ((MinxLCD.Page & 15) * 256)] = data;
            if (++MinxLCD.Column > 131) MinxLCD.Column = 131;
            MinxLCD.RequireDummyR = 1;
            LCDDirty = 4;
        }
    }
}

static void MinxLCD_WriteFB(const uint8_t *fb)
{
    uint8_t *dst = WS->lcd_data;
    for (int p = 0; p < 8; p++, dst += 256, fb += 96) {
        if (MinxLCD.SegmentDir) { for (int i = 0; i < 96; i++) dst[131 - i] = fb[i]; }
        else pm_copy(dst, fb, 96);
    }
    MinxLCD.Page = 7; MinxLCD.Column = 96; MinxLCD.RequireDummyR = 1; MinxLCD.ReadModifyMode = 0;
    LCDDirty = 4;
}

static struct {
    int32_t PRCCnt;
    uint32_t PRCBGBase, PRCSprBase;
    uint8_t PRCMode, PRCRateMatch, PRCMapPX, PRCMapPY, PRCMapTW, PRCMapTH, PRCState;
} MinxPRC;

static const uint8_t PRCInvertBit[256] = {
    0x00,0x80,0x40,0xC0,0x20,0xA0,0x60,0xE0,0x10,0x90,0x50,0xD0,0x30,0xB0,0x70,0xF0,
    0x08,0x88,0x48,0xC8,0x28,0xA8,0x68,0xE8,0x18,0x98,0x58,0xD8,0x38,0xB8,0x78,0xF8,
    0x04,0x84,0x44,0xC4,0x24,0xA4,0x64,0xE4,0x14,0x94,0x54,0xD4,0x34,0xB4,0x74,0xF4,
    0x0C,0x8C,0x4C,0xCC,0x2C,0xAC,0x6C,0xEC,0x1C,0x9C,0x5C,0xDC,0x3C,0xBC,0x7C,0xFC,
    0x02,0x82,0x42,0xC2,0x22,0xA2,0x62,0xE2,0x12,0x92,0x52,0xD2,0x32,0xB2,0x72,0xF2,
    0x0A,0x8A,0x4A,0xCA,0x2A,0xAA,0x6A,0xEA,0x1A,0x9A,0x5A,0xDA,0x3A,0xBA,0x7A,0xFA,
    0x06,0x86,0x46,0xC6,0x26,0xA6,0x66,0xE6,0x16,0x96,0x56,0xD6,0x36,0xB6,0x76,0xF6,
    0x0E,0x8E,0x4E,0xCE,0x2E,0xAE,0x6E,0xEE,0x1E,0x9E,0x5E,0xDE,0x3E,0xBE,0x7E,0xFE,
    0x01,0x81,0x41,0xC1,0x21,0xA1,0x61,0xE1,0x11,0x91,0x51,0xD1,0x31,0xB1,0x71,0xF1,
    0x09,0x89,0x49,0xC9,0x29,0xA9,0x69,0xE9,0x19,0x99,0x59,0xD9,0x39,0xB9,0x79,0xF9,
    0x05,0x85,0x45,0xC5,0x25,0xA5,0x65,0xE5,0x15,0x95,0x55,0xD5,0x35,0xB5,0x75,0xF5,
    0x0D,0x8D,0x4D,0xCD,0x2D,0xAD,0x6D,0xED,0x1D,0x9D,0x5D,0xDD,0x3D,0xBD,0x7D,0xFD,
    0x03,0x83,0x43,0xC3,0x23,0xA3,0x63,0xE3,0x13,0x93,0x53,0xD3,0x33,0xB3,0x73,0xF3,
    0x0B,0x8B,0x4B,0xCB,0x2B,0xAB,0x6B,0xEB,0x1B,0x9B,0x5B,0xDB,0x3B,0xBB,0x7B,0xFB,
    0x07,0x87,0x47,0xC7,0x27,0xA7,0x67,0xE7,0x17,0x97,0x57,0xD7,0x37,0xB7,0x77,0xF7,
    0x0F,0x8F,0x4F,0xCF,0x2F,0xAF,0x6F,0xEF,0x1F,0x9F,0x5F,0xDF,0x3F,0xBF,0x7F,0xFF
};

static inline uint8_t prc_rd(uint32_t addr)
{
    if (addr >= 0x2100u) return PM_ROM[addr & PM_ROM_Mask];
    if (addr >= 0x2000u) return 0xFFu;
    if (addr >= 0x1000u) return PM_RAM[addr - 0x1000u];
    return PM_BIOS[addr];
}

static inline void prc_wr(uint32_t addr, uint8_t v)
{
    if (addr >= 0x1000u && addr < 0x2000u)
        PM_RAM[addr - 0x1000u] = v;
}

static void prc_draw_spr8(uint8_t cfg, int X, int Y, int DrawT, int MaskT)
{
    if (X < -7 || X >= 96 || Y < -7 || Y >= 64) return;
    int vaddr = 0x1000 + ((Y >> 3) * 96) + X;
    if (Y >= 0) {
        for (int xC = 0; xC < 8; xC++, X++) {
            if (X >= 0 && X < 96) {
                int xP = (cfg & 1) ? (7 - xC) : xC;
                uint8_t vdata = prc_rd((uint32_t)(vaddr + xC));
                uint8_t sdata = prc_rd(MinxPRC.PRCSprBase + (uint32_t)(DrawT * 8 + xP));
                uint8_t smask = prc_rd(MinxPRC.PRCSprBase + (uint32_t)(MaskT * 8 + xP));
                if (cfg & 2) { sdata = PRCInvertBit[sdata]; smask = PRCInvertBit[smask]; }
                if (cfg & 4) sdata = ~sdata;
                uint8_t data = vdata & ((uint8_t)(smask << (Y & 7)) | (uint8_t)(0xFFu >> (8 - (Y & 7))));
                data |= (uint8_t)((sdata & ~smask) << (Y & 7));
                prc_wr((uint32_t)(vaddr + xC), data);
            }
        }
        X -= 8;
    }
    vaddr += 96;
    if (Y < 56 && (Y & 7)) {
        for (int xC = 0; xC < 8; xC++, X++) {
            if (X >= 0 && X < 96) {
                int xP = (cfg & 1) ? (7 - xC) : xC;
                uint8_t vdata = prc_rd((uint32_t)(vaddr + xC));
                uint8_t sdata = prc_rd(MinxPRC.PRCSprBase + (uint32_t)(DrawT * 8 + xP));
                uint8_t smask = prc_rd(MinxPRC.PRCSprBase + (uint32_t)(MaskT * 8 + xP));
                if (cfg & 2) { sdata = PRCInvertBit[sdata]; smask = PRCInvertBit[smask]; }
                if (cfg & 4) sdata = ~sdata;
                uint8_t data = vdata & ((uint8_t)(smask >> (8 - (Y & 7))) | (uint8_t)(0xFFu << (Y & 7)));
                data |= (uint8_t)((sdata & ~smask) >> (8 - (Y & 7)));
                prc_wr((uint32_t)(vaddr + xC), data);
            }
        }
    }
}

static void MinxPRC_RenderMono(void)
{
    if (PMR_PRC_MODE & 0x02) {
        uint32_t outaddr = 0x1000u, tiletop = 0, tilebot = 0;
        int ltile = -1;
        for (int yC = 0; yC < 8; yC++) {
            int ty = (yC << 3) + MinxPRC.PRCMapPY;
            for (int xC = 0; xC < 96; xC++) {
                int tx = xC + MinxPRC.PRCMapPX;
                int tidx = 0x1360 + (ty >> 3) * MinxPRC.PRCMapTW + (tx >> 3);
                if (ltile != tidx) {
                    tiletop = MinxPRC.PRCBGBase + (uint32_t)prc_rd((uint32_t)tidx) * 8u;
                    tilebot = MinxPRC.PRCBGBase + (uint32_t)prc_rd((uint32_t)(tidx + MinxPRC.PRCMapTW)) * 8u;
                    ltile = tidx;
                }
                uint8_t data = (uint8_t)((prc_rd(tiletop + (uint32_t)(tx & 7)) >> (ty & 7))
                                       | (prc_rd(tilebot + (uint32_t)(tx & 7)) << (8 - (ty & 7))));
                prc_wr(outaddr++, (PMR_PRC_MODE & 1) ? (uint8_t)~data : data);
            }
        }
    }
    if (PMR_PRC_MODE & 0x04) {
        uint32_t sa = 0x1300u + 24u * 4u;
        do {
            uint8_t sc = prc_rd(--sa);
            int stb = (int)prc_rd(--sa) * 8;
            int sy = (int)(prc_rd(--sa) & 0x7Fu) - 16;
            int sx = (int)(prc_rd(--sa) & 0x7Fu) - 16;
            if (sc & 0x08) {
                int fx = (sc & 1) ? 8 : 0;
                int fy = (sc & 2) ? 8 : 0;
                prc_draw_spr8(sc, sx + fx, sy + fy, stb + 2, stb);
                prc_draw_spr8(sc, sx + fx, sy + 8 - fy, stb + 3, stb + 1);
                prc_draw_spr8(sc, sx + 8 - fx, sy + fy, stb + 6, stb + 4);
                prc_draw_spr8(sc, sx + 8 - fx, sy + 8 - fy, stb + 7, stb + 5);
            }
        } while (sa > 0x1300u);
    }
}

static void MinxPRC_Sync(void)
{
    MinxPRC.PRCCnt += (16777216 / 855) * PokeHWCycles;
    if ((PMR_PRC_RATE & 0xF0) >= MinxPRC.PRCRateMatch) {
        if (MinxPRC.PRCCnt < 0x18000000) {
            MinxPRC.PRCState = 0;
        } else if ((MinxPRC.PRCCnt & 0xFF000000u) == 0x18000000u) {
            if (MinxPRC.PRCState == 1) return;
            if (MinxPRC.PRCMode == 2) {
                StallCPU = 1;
                MinxPRC_RenderMono();
                MinxPRC.PRCState = 1;
            }
        } else if ((MinxPRC.PRCCnt & 0xFF000000u) == 0x39000000u) {
            if (MinxPRC.PRCState == 2) return;
            if (MinxPRC.PRCMode) {
                StallCPU = 1;
                MinxLCD_WriteFB(PM_RAM);
                MinxCPU_OnIRQAct(0x03);
                MinxPRC.PRCState = 2;
            }
        } else if (MinxPRC.PRCCnt >= 0x42000000) {
            StallCPU = 0;
            PMR_PRC_RATE &= 0x0F;
            MinxPRC.PRCCnt = 0x01000000;
            MinxCPU_OnIRQAct(0x04);
            if (LCDDirty) { MinxLCD_Render(); LCDDirty = 0; }
            MinxLCD_DecayRefresh();
            PokeMini_FrameDone = 1;
        }
    } else {
        if (MinxPRC.PRCCnt >= 0x42000000) {
            PMR_PRC_RATE += 0x10;
            MinxPRC.PRCCnt = 0x01000000;
            if (LCDDirty) { MinxLCD_Render(); LCDDirty = 0; }
            MinxLCD_DecayRefresh();
            PokeMini_FrameDone = 1;
        }
    }
}

static uint8_t MinxPRC_ReadReg(uint8_t reg)
{
    switch (reg) {
    case 0x80: return PMR_PRC_MODE & 0x3F;
    case 0x81: return PMR_PRC_RATE;
    case 0x82: return PMR_PRC_MAP_LO & 0xF8;
    case 0x83: return PMR_PRC_MAP_MID;
    case 0x84: return PMR_PRC_MAP_HI & 0x1F;
    case 0x85: return PMR_PRC_SCROLL_Y & 0x7F;
    case 0x86: return PMR_PRC_SCROLL_X & 0x7F;
    case 0x87: return PMR_PRC_SPR_LO & 0xC0;
    case 0x88: return PMR_PRC_SPR_MID;
    case 0x89: return PMR_PRC_SPR_HI & 0x1F;
    case 0x8A: return (uint8_t)(MinxPRC.PRCCnt >> 24);
    }
    return 0;
}

static void MinxPRC_WriteReg(uint8_t reg, uint8_t val)
{
    switch (reg) {
    case 0x80:
        PMR_PRC_MODE = val & 0x3F;
        MinxPRC.PRCMode = (val & 0x08) ? ((val & 0x06) ? 2 : 1) : 0;
        switch (val & 0x30) {
        case 0x00: MinxPRC.PRCMapTW = 12; MinxPRC.PRCMapTH = 16; break;
        case 0x10: MinxPRC.PRCMapTW = 16; MinxPRC.PRCMapTH = 12; break;
        case 0x20: MinxPRC.PRCMapTW = 24; MinxPRC.PRCMapTH = 8; break;
        case 0x30: MinxPRC.PRCMapTW = 24; MinxPRC.PRCMapTH = 16; break;
        }
        break;
    case 0x81:
        if ((PMR_PRC_RATE & 0x0E) != (val & 0x0E)) PMR_PRC_RATE = val & 0x0F;
        else PMR_PRC_RATE = (PMR_PRC_RATE & 0xF0) | (val & 0x0F);
        switch (val & 0x0E) {
        case 0x00: MinxPRC.PRCRateMatch = 0x20; break;
        case 0x02: MinxPRC.PRCRateMatch = 0x50; break;
        case 0x04: MinxPRC.PRCRateMatch = 0x80; break;
        case 0x06: MinxPRC.PRCRateMatch = 0xB0; break;
        case 0x08: MinxPRC.PRCRateMatch = 0x10; break;
        case 0x0A: MinxPRC.PRCRateMatch = 0x30; break;
        case 0x0C: MinxPRC.PRCRateMatch = 0x50; break;
        case 0x0E: MinxPRC.PRCRateMatch = 0x70; break;
        }
        break;
    case 0x82: PMR_PRC_MAP_LO = val & 0xF8; MinxPRC.PRCBGBase = (MinxPRC.PRCBGBase & 0x1FFF00u) | PMR_PRC_MAP_LO; break;
    case 0x83: PMR_PRC_MAP_MID = val; MinxPRC.PRCBGBase = (MinxPRC.PRCBGBase & 0x1F00F8u) | ((uint32_t)val << 8); break;
    case 0x84: PMR_PRC_MAP_HI = val & 0x1F; MinxPRC.PRCBGBase = (MinxPRC.PRCBGBase & 0x00FFF8u) | ((uint32_t)PMR_PRC_MAP_HI << 16); break;
    case 0x85: PMR_PRC_SCROLL_Y = val & 0x7F; if (PMR_PRC_SCROLL_Y <= (MinxPRC.PRCMapTH * 8 - 64)) MinxPRC.PRCMapPY = PMR_PRC_SCROLL_Y; break;
    case 0x86: PMR_PRC_SCROLL_X = val & 0x7F; if (PMR_PRC_SCROLL_X <= (MinxPRC.PRCMapTW * 8 - 96)) MinxPRC.PRCMapPX = PMR_PRC_SCROLL_X; break;
    case 0x87: PMR_PRC_SPR_LO = val & 0xC0; MinxPRC.PRCSprBase = (MinxPRC.PRCSprBase & 0x1FFF00u) | PMR_PRC_SPR_LO; break;
    case 0x88: PMR_PRC_SPR_MID = val; MinxPRC.PRCSprBase = (MinxPRC.PRCSprBase & 0x1F00C0u) | ((uint32_t)val << 8); break;
    case 0x89: PMR_PRC_SPR_HI = val & 0x1F; MinxPRC.PRCSprBase = (MinxPRC.PRCSprBase & 0x00FFC0u) | ((uint32_t)PMR_PRC_SPR_HI << 16); break;
    }
}

static void MinxAudio_WriteReg(uint8_t reg, uint8_t val)
{
    if (reg == 0x70) PMR_AUD_CTRL = val & 0x07;
    else if (reg == 0x71) PMR_AUD_VOL = val & 0x07;

    if (PMR_AUD_CTRL & 0x03) {
        pm_aud_vol = 0;
        pm_pwm_mul = 0;
    } else {
        switch (PMR_AUD_VOL & 3) {
        case 0:  pm_aud_vol = 0;      pm_pwm_mul = 0; break;
        case 1:
        case 2:  pm_aud_vol = 0x2000; pm_pwm_mul = 1; break;
        default: pm_aud_vol = 0x4000; pm_pwm_mul = 2; break;
        }
    }
}

static int16_t pm_piezo(int32_t s)
{
    int32_t t0 = s;
    int32_t t1 = (40960 * (t0 + pm_hp[1] - pm_hp[0])) >> 16;
    int32_t t2 = (40960 * (t1 + pm_hp[2] - pm_hp[1])) >> 16;
    int32_t t3 = (40960 * (t2 + pm_hp[3] - pm_hp[2])) >> 16;
    pm_hp[0] = t0; pm_hp[1] = t1; pm_hp[2] = t2; pm_hp[3] = t3;
    s = t3 << 2;
    if (s < -32768) s = -32768; else if (s > 32767) s = 32767;
    pm_lp[0] = s;
    pm_lp[1] = (pm_lp[1] * 4096 + pm_lp[0] * 61439) >> 16;
    pm_lp[2] = (pm_lp[2] * 4096 + pm_lp[1] * 61439) >> 16;
    pm_lp[3] = (pm_lp[3] * 4096 + pm_lp[2] * 61439) >> 16;
    s = pm_lp[3] << 1;
    if (s < -32768) return -32768;
    if (s > 32767) return 32767;
    return (int16_t)s;
}

static void MinxAudio_Sync(void)
{
    if (!pm_snd_hz) return;
    pm_aud_ccnt += (int32_t)(pm_snd_inc * (uint32_t)PokeHWCycles);
    while (pm_aud_ccnt >= 0x01000000) {
        pm_aud_ccnt -= 0x01000000;
        uint32_t pwm = 0;
        uint16_t cnt = (uint16_t)((MinxTimers.Tmr3CntA >> 24) | ((MinxTimers.Tmr3CntB >> 24) << 8));
        uint16_t pre = (uint16_t)((MinxTimers.Tmr3PreA >> 24) | ((MinxTimers.Tmr3PreB >> 24) << 8));
        if (pre) pwm = (uint32_t)MinxTimers.Timer3Piv * 0x1FFFu / pre;
        if (pwm >= 0x1FFFu) pwm = 0x1FFEu;
        if (pre < 128u) cnt = 0;
        int32_t raw = ((cnt <= MinxTimers.Timer3Piv) ? pm_aud_vol : 0) + (int32_t)pwm * pm_pwm_mul;
        int16_t out = pm_piezo(raw);
        if ((pm_snd_wr - pm_snd_rd) <= PM_RING_MASK)
            WS->snd_ring[pm_snd_wr++ & PM_RING_MASK] = out;
    }
}

static uint8_t MinxCPU_OnRead(int cpu, uint32_t addr)
{
    if (addr >= 0x200000u) return MinxCPU.IR;
    if (addr >= 0x2100u) return PM_ROM[addr & PM_ROM_Mask];
    if (addr >= 0x2000u) {
        uint8_t reg = (uint8_t)addr;
        switch (reg) {
        case 0x00: return PMR_SYS_CTRL1;
        case 0x01: return PMR_SYS_CTRL2;
        case 0x02: return PMR_SYS_CTRL3;
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
        case 0x26: case 0x27: case 0x28: case 0x29: case 0x2A:
            return MinxIRQ_ReadReg(reg);
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E: case 0x1F:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D: case 0x3E: case 0x3F:
        case 0x40: case 0x41:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            return MinxTimers_ReadReg(reg);
        case 0x10:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x60: case 0x61: case 0x62:
            return MinxIO_ReadReg(reg);
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            return MinxPRC_ReadReg(reg);
        case 0xFE: case 0xFF:
            return MinxLCD_ReadReg(cpu, reg);
        case 0x70: return PMR_AUD_CTRL & 7;
        case 0x71: return PMR_AUD_VOL & 7;
        case 0xF0: case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF7:
            return 0;
        default: return MinxCPU.IR;
        }
    }
    if (addr >= 0x1000u) return PM_RAM[addr - 0x1000u];
    return PM_BIOS[addr];
}

static void MinxCPU_OnWrite(int cpu, uint32_t addr, uint8_t data)
{
    if (addr >= 0x2100u) return;
    if (addr >= 0x2000u) {
        uint8_t reg = (uint8_t)addr;
        switch (reg) {
        case 0x00: PMR_SYS_CTRL1 = data; return;
        case 0x01: PMR_SYS_CTRL2 = data; return;
        case 0x02: PMR_SYS_CTRL3 = data; return;
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
        case 0x26: case 0x27: case 0x28: case 0x29: case 0x2A:
            MinxIRQ_WriteReg(cpu, reg, data); return;
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E: case 0x1F:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D: case 0x3E: case 0x3F:
        case 0x40: case 0x41:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            MinxTimers_WriteReg(reg, data); return;
        case 0x10:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x60: case 0x61: case 0x62:
            MinxIO_WriteReg(reg, data); return;
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A:
            MinxPRC_WriteReg(reg, data); return;
        case 0xFE: case 0xFF:
            MinxLCD_WriteReg(reg, data); return;
        case 0x70: case 0x71:
            MinxAudio_WriteReg(reg, data); return;
        }
        return;
    }
    if (addr >= 0x1000u)
        PM_RAM[addr - 0x1000u] = data;
}


// Note: Any write to MinxCPU.HL.B.I needs to be reflected into MinxCPU.N.B.I

static __attribute__((noinline)) int MinxCPU_Exec(void)
{
	uint8_t I8A, I8B;
	uint16_t I16;

	// Shift U
	if (MinxCPU.Shift_U) {
		MinxCPU.U1 = MinxCPU.U2;
		MinxCPU.U2 = MinxCPU.PC.B.I;
		MinxCPU.Shift_U--;
		MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
	}

	// Check HALT or STOP status
	if (MinxCPU.Status != MINX_STATUS_NORMAL) {
		if (MinxCPU.Status == MINX_STATUS_IRQ) {
			MinxCPU.Status = MINX_STATUS_NORMAL;	// Return to normal
			CALLI(MinxCPU.IRQ_Vector);		// Jump to IRQ vector
			return 20;
		} else {
			return 8;				// Cause short NOPs
		}
	}

	// Read IR
	MinxCPU.IR = Fetch8();

	// Process instruction
	switch(MinxCPU.IR) {

		case 0x00: // ADD A, A
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x01: // ADD A, B
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x02: // ADD A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x03: // ADD A, [HL]
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x04: // ADD A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x05: // ADD A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x06: // ADD A, [X]
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x07: // ADD A, [Y]
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x08: // ADC A, A
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x09: // ADC A, B
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x0A: // ADC A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x0B: // ADC A, [HL]
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x0C: // ADC A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x0D: // ADC A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x0E: // ADC A, [X]
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x0F: // ADC A, [Y]
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x10: // SUB A, A
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x11: // SUB A, B
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x12: // SUB A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x13: // SUB A, [HL]
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x14: // SUB A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x15: // SUB A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x16: // SUB A, [X]
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x17: // SUB A, [Y]
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x18: // SBC A, A
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x19: // SBC A, B
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x1A: // SBC A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x1B: // SBC A, [HL]
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x1C: // SBC A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x1D: // SBC A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x1E: // SBC A, [X]
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x1F: // SBC A, [Y]
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x20: // AND A, A
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x21: // AND A, B
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x22: // AND A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x23: // AND A, [HL]
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x24: // AND A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x25: // AND A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x26: // AND A, [X]
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x27: // AND A, [Y]
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x28: // OR A, A
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x29: // OR A, B
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x2A: // OR A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x2B: // OR A, [HL]
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x2C: // OR A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x2D: // OR A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x2E: // OR A, [X]
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x2F: // OR A, [Y]
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x30: // CMP A, A
			SUB8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x31: // CMP A, B
			SUB8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x32: // CMP A, #nn
			I8A = Fetch8();
			SUB8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x33: // CMP A, [HL]
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x34: // CMP A, [N+#nn]
			I8A = Fetch8();
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x35: // CMP A, [#nnnn]
			I16 = Fetch16();
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x36: // CMP A, [X]
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x37: // CMP A, [Y]
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x38: // XOR A, A
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU.BA.B.L);
			return 8;
		case 0x39: // XOR A, B
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x3A: // XOR A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x3B: // XOR A, [HL]
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 8;
		case 0x3C: // XOR A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 12;
		case 0x3D: // XOR A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16));
			return 16;
		case 0x3E: // XOR A, [X]
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 8;
		case 0x3F: // XOR A, [Y]
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 8;

		case 0x40: // MOV A, A
			return 4;
		case 0x41: // MOV A, B
			MinxCPU.BA.B.L = MinxCPU.BA.B.H;
			return 4;
		case 0x42: // MOV A, L
			MinxCPU.BA.B.L = MinxCPU.HL.B.L;
			return 4;
		case 0x43: // MOV A, H
			MinxCPU.BA.B.L = MinxCPU.HL.B.H;
			return 4;
		case 0x44: // MOV A, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, MinxCPU.N.D + I8A);
			return 12;
		case 0x45: // MOV A, [HL]
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, MinxCPU.HL.D);
			return 8;
		case 0x46: // MOV A, [X]
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, MinxCPU.X.D);
			return 8;
		case 0x47: // MOV A, [Y]
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, MinxCPU.Y.D);
			return 8;

		case 0x48: // MOV B, A
			MinxCPU.BA.B.H = MinxCPU.BA.B.L;
			return 4;
		case 0x49: // MOV B, B
			return 4;
		case 0x4A: // MOV B, L
			MinxCPU.BA.B.H = MinxCPU.HL.B.L;
			return 4;
		case 0x4B: // MOV B, H
			MinxCPU.BA.B.H = MinxCPU.HL.B.H;
			return 4;
		case 0x4C: // MOV B, [N+#nn]
			I8A = Fetch8();
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, MinxCPU.N.D + I8A);
			return 12;
		case 0x4D: // MOV B, [HL]
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, MinxCPU.HL.D);
			return 8;
		case 0x4E: // MOV B, [X]
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, MinxCPU.X.D);
			return 8;
		case 0x4F: // MOV B, [Y]
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, MinxCPU.Y.D);
			return 8;

		case 0x50: // MOV L, A
			MinxCPU.HL.B.L = MinxCPU.BA.B.L;
			return 4;
		case 0x51: // MOV L, B
			MinxCPU.HL.B.L = MinxCPU.BA.B.H;
			return 4;
		case 0x52: // MOV L, L
			return 4;
		case 0x53: // MOV L, H
			MinxCPU.HL.B.L = MinxCPU.HL.B.H;
			return 4;
		case 0x54: // MOV L, [N+#nn]
			I8A = Fetch8();
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, MinxCPU.N.D + I8A);
			return 12;
		case 0x55: // MOV L, [HL]
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, MinxCPU.HL.D);
			return 8;
		case 0x56: // MOV L, [X]
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, MinxCPU.X.D);
			return 8;
		case 0x57: // MOV L, [Y]
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, MinxCPU.Y.D);
			return 8;

		case 0x58: // MOV H, A
			MinxCPU.HL.B.H = MinxCPU.BA.B.L;
			return 4;
		case 0x59: // MOV H, B
			MinxCPU.HL.B.H = MinxCPU.BA.B.H;
			return 4;
		case 0x5A: // MOV H, L
			MinxCPU.HL.B.H = MinxCPU.HL.B.L;
			return 4;
		case 0x5B: // MOV H, H
			return 4;
		case 0x5C: // MOV H, [N+#nn]
			I8A = Fetch8();
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, MinxCPU.N.D + I8A);
			return 12;
		case 0x5D: // MOV H, [HL]
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, MinxCPU.HL.D);
			return 8;
		case 0x5E: // MOV H, [X]
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, MinxCPU.X.D);
			return 8;
		case 0x5F: // MOV H, [Y]
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, MinxCPU.Y.D);
			return 8;

		case 0x60: // MOV [X], A
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU.BA.B.L);
			return 8;
		case 0x61: // MOV [X], B
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU.BA.B.H);
			return 8;
		case 0x62: // MOV [X], L
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU.HL.B.L);
			return 8;
		case 0x63: // MOV [X], H
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU.HL.B.H);
			return 8;
		case 0x64: // MOV [X], [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 16;
		case 0x65: // MOV [X], [HL]
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 12;
		case 0x66: // MOV [X], [X]
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 12;
		case 0x67: // MOV [X], [Y]
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 12;

		case 0x68: // MOV [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU.BA.B.L);
			return 8;
		case 0x69: // MOV [HL], B
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU.BA.B.H);
			return 8;
		case 0x6A: // MOV [HL], L
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU.HL.B.L);
			return 8;
		case 0x6B: // MOV [HL], H
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU.HL.B.H);
			return 8;
		case 0x6C: // MOV [HL], [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 16;
		case 0x6D: // MOV [HL], [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 12;
		case 0x6E: // MOV [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 12;
		case 0x6F: // MOV [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 12;

		case 0x70: // MOV [Y], A
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU.BA.B.L);
			return 8;
		case 0x71: // MOV [Y], B
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU.BA.B.H);
			return 8;
		case 0x72: // MOV [Y], L
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU.HL.B.L);
			return 8;
		case 0x73: // MOV [Y], H
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU.HL.B.H);
			return 8;
		case 0x74: // MOV [Y], [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, MinxCPU.N.D + I8A));
			return 16;
		case 0x75: // MOV [Y], [HL]
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 12;
		case 0x76: // MOV [Y], [X]
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 12;
		case 0x77: // MOV [Y], [Y]
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 12;

		case 0x78: // MOV [N+#nn], A
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU.BA.B.L);
			return 8;
		case 0x79: // MOV [N+#nn], B
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU.BA.B.H);
			return 8;
		case 0x7A: // MOV [N+#nn], L
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU.HL.B.L);
			return 8;
		case 0x7B: // MOV [N+#nn], H
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU.HL.B.H);
			return 8;
		case 0x7C: // NOTHING #nn
			I8A = Fetch8();
			return 64;
		case 0x7D: // MOV [N+#nn], [HL]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU_OnRead(1, MinxCPU.HL.D));
			return 16;
		case 0x7E: // MOV [N+#nn], [X]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU_OnRead(1, MinxCPU.X.D));
			return 16;
		case 0x7F: // MOV [N+#nn], [Y]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 16;

		case 0x80: // INC A
			MinxCPU.BA.B.L = INC8(MinxCPU.BA.B.L);
			return 8;
		case 0x81: // INC B
			MinxCPU.BA.B.H = INC8(MinxCPU.BA.B.H);
			return 8;
		case 0x82: // INC L
			MinxCPU.HL.B.L = INC8(MinxCPU.HL.B.L);
			return 8;
		case 0x83: // INC H
			MinxCPU.HL.B.H = INC8(MinxCPU.HL.B.H);
			return 8;
		case 0x84: // INC N
			MinxCPU.N.B.H = INC8(MinxCPU.N.B.H);
			return 8;
		case 0x85: // INC [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, INC8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A)));
			return 16;
		case 0x86: // INC [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, INC8(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 12;
		case 0x87: // INC SP
			MinxCPU.SP.W.L = INC16(MinxCPU.SP.W.L);
			return 8;

		case 0x88: // DEC A
			MinxCPU.BA.B.L = DEC8(MinxCPU.BA.B.L);
			return 8;
		case 0x89: // DEC B
			MinxCPU.BA.B.H = DEC8(MinxCPU.BA.B.H);
			return 8;
		case 0x8A: // DEC L
			MinxCPU.HL.B.L = DEC8(MinxCPU.HL.B.L);
			return 8;
		case 0x8B: // DEC H
			MinxCPU.HL.B.H = DEC8(MinxCPU.HL.B.H);
			return 8;
		case 0x8C: // DEC N
			MinxCPU.N.B.H = DEC8(MinxCPU.N.B.H);
			return 8;
		case 0x8D: // DEC [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, DEC8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A)));
			return 16;
		case 0x8E: // DEC [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, DEC8(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 12;
		case 0x8F: // DEC SP
			MinxCPU.SP.W.L = DEC16(MinxCPU.SP.W.L);
			return 8;

		case 0x90: // INC BA
			MinxCPU.BA.W.L = INC16(MinxCPU.BA.W.L);
			return 8;
		case 0x91: // INC HL
			MinxCPU.HL.W.L = INC16(MinxCPU.HL.W.L);
			return 8;
		case 0x92: // INC X
			MinxCPU.X.W.L = INC16(MinxCPU.X.W.L);
			return 8;
		case 0x93: // INC Y
			MinxCPU.Y.W.L = INC16(MinxCPU.Y.W.L);
			return 8;

		case 0x94: // TST A, B
			AND8(MinxCPU.BA.B.L, MinxCPU.BA.B.H);
			return 8;
		case 0x95: // TST [HL], #nn
			I8A = Fetch8();
			AND8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A);
			return 12;
		case 0x96: // TST A, #nn
			I8A = Fetch8();
			AND8(MinxCPU.BA.B.L, I8A);
			return 8;
		case 0x97: // TST B, #nn
			I8A = Fetch8();
			AND8(MinxCPU.BA.B.H, I8A);
			return 8;

		case 0x98: // DEC BA
			MinxCPU.BA.W.L = DEC16(MinxCPU.BA.W.L);
			return 8;
		case 0x99: // DEC HL
			MinxCPU.HL.W.L = DEC16(MinxCPU.HL.W.L);
			return 8;
		case 0x9A: // DEC X
			MinxCPU.X.W.L = DEC16(MinxCPU.X.W.L);
			return 8;
		case 0x9B: // DEC Y
			MinxCPU.Y.W.L = DEC16(MinxCPU.Y.W.L);
			return 8;

		case 0x9C: // AND F, #nn
			I8A = Fetch8();
			MinxCPU.F = MinxCPU.F & I8A;
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 12;
		case 0x9D: // OR F, #nn
			I8A = Fetch8();
			MinxCPU.F = MinxCPU.F | I8A;
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 12;
		case 0x9E: // XOR F, #nn
			I8A = Fetch8();
			MinxCPU.F = MinxCPU.F ^ I8A;
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 12;
		case 0x9F: // MOV F, #nn
			I8A = Fetch8();
			MinxCPU.F = I8A;
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 12;

		case 0xA0: // PUSH BA
			PUSH(MinxCPU.BA.B.H);
			PUSH(MinxCPU.BA.B.L);
			return 16;
		case 0xA1: // PUSH HL
			PUSH(MinxCPU.HL.B.H);
			PUSH(MinxCPU.HL.B.L);
			return 16;
		case 0xA2: // PUSH X
			PUSH(MinxCPU.X.B.H);
			PUSH(MinxCPU.X.B.L);
			return 16;
		case 0xA3: // PUSH Y
			PUSH(MinxCPU.Y.B.H);
			PUSH(MinxCPU.Y.B.L);
			return 16;
		case 0xA4: // PUSH N
			PUSH(MinxCPU.N.B.H);
			return 12;
		case 0xA5: // PUSH I
			PUSH(MinxCPU.HL.B.I);
			return 12;
		case 0xA6: // PUSHX
			PUSH(MinxCPU.X.B.I);
			PUSH(MinxCPU.Y.B.I);
			return 16;
		case 0xA7: // PUSH F
			PUSH(MinxCPU.F);
			return 12;

		case 0xA8: // POP BA
			MinxCPU.BA.B.L = POP();
			MinxCPU.BA.B.H = POP();
			return 12;
		case 0xA9: // POP HL
			MinxCPU.HL.B.L = POP();
			MinxCPU.HL.B.H = POP();
			return 12;
		case 0xAA: // POP X
			MinxCPU.X.B.L = POP();
			MinxCPU.X.B.H = POP();
			return 12;
		case 0xAB: // POP Y
			MinxCPU.Y.B.L = POP();
			MinxCPU.Y.B.H = POP();
			return 12;
		case 0xAC: // POP N
			MinxCPU.N.B.H = POP();
			return 8;
		case 0xAD: // POP I
			MinxCPU.HL.B.I = POP();
			MinxCPU.N.B.I = MinxCPU.HL.B.I;
			return 8;
		case 0xAE: // POPX
			MinxCPU.Y.B.I = POP();
			MinxCPU.X.B.I = POP();
			return 12;
		case 0xAF: // POP F
			MinxCPU.F = POP();
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 8;

		case 0xB0: // MOV A, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.L = I8A;
			return 8;
		case 0xB1: // MOV B, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.H = I8A;
			return 8;
		case 0xB2: // MOV L, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.L = I8A;
			return 8;
		case 0xB3: // MOV H, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.H = I8A;
			return 8;
		case 0xB4: // MOV N, #nn
			I8A = Fetch8();
			MinxCPU.N.B.H = I8A;
			return 8;
		case 0xB5: // MOV [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, I8A);
			return 12;
		case 0xB6: // MOV [X], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.X.D, I8A);
			return 12;
		case 0xB7: // MOV [Y], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.Y.D, I8A);
			return 12;

		case 0xB8: // MOV BA, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xB9: // MOV HL, [#nnnn]
			I16 = Fetch16();
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xBA: // MOV X, [#nnnn]
			I16 = Fetch16();
			MinxCPU.X.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.X.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xBB: // MOV Y, [#nnnn]
			I16 = Fetch16();
			MinxCPU.Y.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.Y.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;

		case 0xBC: // MOV [#nnnn], BA
			I16 = Fetch16();
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.BA.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 20;
		case 0xBD: // MOV [#nnnn], HL
			I16 = Fetch16();
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 20;
		case 0xBE: // MOV [#nnnn], X
			I16 = Fetch16();
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.X.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.X.B.H);
			return 20;
		case 0xBF: // MOV [#nnnn], Y
			I16 = Fetch16();
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.Y.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.Y.B.H);
			return 20;

		case 0xC0: // ADD BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, I16);
			return 12;
		case 0xC1: // ADD HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, I16);
			return 12;
		case 0xC2: // ADD X, #nnnn
			I16 = Fetch16();
			MinxCPU.X.W.L = ADD16(MinxCPU.X.W.L, I16);
			return 12;
		case 0xC3: // ADD Y, #nnnn
			I16 = Fetch16();
			MinxCPU.Y.W.L = ADD16(MinxCPU.Y.W.L, I16);
			return 12;

		case 0xC4: // MOV BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = I16;
			return 12;
		case 0xC5: // MOV HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = I16;
			return 12;
		case 0xC6: // MOV X, #nnnn
			I16 = Fetch16();
			MinxCPU.X.W.L = I16;
			return 12;
		case 0xC7: // MOV Y, #nnnn
			I16 = Fetch16();
			MinxCPU.Y.W.L = I16;
			return 12;

		case 0xC8: // XCHG BA, HL
			I16 = MinxCPU.HL.W.L;
			MinxCPU.HL.W.L = MinxCPU.BA.W.L;
			MinxCPU.BA.W.L = I16;
			return 12;
		case 0xC9: // XCHG BA, X
			I16 = MinxCPU.X.W.L;
			MinxCPU.X.W.L = MinxCPU.BA.W.L;
			MinxCPU.BA.W.L = I16;
			return 12;
		case 0xCA: // XCHG BA, Y
			I16 = MinxCPU.Y.W.L;
			MinxCPU.Y.W.L = MinxCPU.BA.W.L;
			MinxCPU.BA.W.L = I16;
			return 12;
		case 0xCB: // XCHG BA, SP
			I16 = MinxCPU.SP.W.L;
			MinxCPU.SP.W.L = MinxCPU.BA.W.L;
			MinxCPU.BA.W.L = I16;
			return 12;

		case 0xCC: // XCHG A, B
			I8A = MinxCPU.BA.B.H;
			MinxCPU.BA.B.H = MinxCPU.BA.B.L;
			MinxCPU.BA.B.L = I8A;
			return 8;
		case 0xCD: // XCHG A, [HL]
			I8A = MinxCPU_OnRead(1, MinxCPU.HL.D);
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU.BA.B.L);
			MinxCPU.BA.B.L = I8A;
			return 12;

		case 0xCE: // Expand 0
			return MinxCPU_ExecCE();

		case 0xCF: // Expand 1
			return MinxCPU_ExecCF();

		case 0xD0: // SUB BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = SUB16(MinxCPU.BA.W.L, I16);
			return 12;
		case 0xD1: // SUB HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = SUB16(MinxCPU.HL.W.L, I16);
			return 12;
		case 0xD2: // SUB X, #nnnn
			I16 = Fetch16();
			MinxCPU.X.W.L = SUB16(MinxCPU.X.W.L, I16);
			return 12;
		case 0xD3: // SUB Y, #nnnn
			I16 = Fetch16();
			MinxCPU.Y.W.L = SUB16(MinxCPU.Y.W.L, I16);
			return 12;

		case 0xD4: // CMP BA, #nnnn
			I16 = Fetch16();
			SUB16(MinxCPU.BA.W.L, I16);
			return 12;
		case 0xD5: // CMP HL, #nnnn
			I16 = Fetch16();
			SUB16(MinxCPU.HL.W.L, I16);
			return 12;
		case 0xD6: // CMP X, #nnnn
			I16 = Fetch16();
			SUB16(MinxCPU.X.W.L, I16);
			return 12;
		case 0xD7: // CMP Y, #nnnn
			I16 = Fetch16();
			SUB16(MinxCPU.Y.W.L, I16);
			return 12;

		case 0xD8: // AND [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, AND8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A), I8B));
			return 20;
		case 0xD9: // OR [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, OR8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A), I8B));
			return 20;
		case 0xDA: // XOR [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, XOR8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A), I8B));
			return 20;
		case 0xDB: // CMP [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			SUB8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A), I8B);
			return 16;
		case 0xDC: // TST [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			AND8(MinxCPU_OnRead(1, MinxCPU.N.D + I8A), I8B);
			return 16;
		case 0xDD: // MOV [N+#nn], #nn
			I8A = Fetch8();
			I8B = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D + I8A, I8B);
			return 16;

		case 0xDE: // PACK
			MinxCPU.BA.B.L = (MinxCPU.BA.B.L & 0x0F) | (MinxCPU.BA.B.H << 4);
			return 8;

		case 0xDF: // UNPACK
			MinxCPU.BA.B.H = (MinxCPU.BA.B.L >> 4);
			MinxCPU.BA.B.L = MinxCPU.BA.B.L & 0x0F;
			return 8;

		case 0xE0: // CALLC #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_CARRY) {
				CALLS(S8_TO_16(I8A));
				return 20;
			}
			return 8;
		case 0xE1: // CALLNC #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) {
				CALLS(S8_TO_16(I8A));
				return 20;
			}
			return 8;
		case 0xE2: // CALLZ #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_ZERO) {
				CALLS(S8_TO_16(I8A));
				return 20;
			}
			return 8;
		case 0xE3: // CALLNZ #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_ZERO)) {
				CALLS(S8_TO_16(I8A));
				return 20;
			}
			return 8;

		case 0xE4: // JC #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_CARRY) {
				JMPS(S8_TO_16(I8A));
			}
			return 8;
		case 0xE5: // JNC #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) {
				JMPS(S8_TO_16(I8A));
			}
			return 8;
		case 0xE6: // JZ #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_ZERO) {
				JMPS(S8_TO_16(I8A));
			}
			return 8;
		case 0xE7: // JNZ #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_ZERO)) {
				JMPS(S8_TO_16(I8A));
			}
			return 8;

		case 0xE8: // CALLC #ssss
			I16 = Fetch16();
			if (MinxCPU.F & MINX_FLAG_CARRY) {
				CALLS(I16);
				return 24;
			}
			return 12;
		case 0xE9: // CALLNC #ssss
			I16 = Fetch16();
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) {
				CALLS(I16);
				return 24;
			}
			return 12;
		case 0xEA: // CALLZ #ssss
			I16 = Fetch16();
			if (MinxCPU.F & MINX_FLAG_ZERO) {
				CALLS(I16);
				return 24;
			}
			return 12;
		case 0xEB: // CALLNZ #ssss
			I16 = Fetch16();
			if (!(MinxCPU.F & MINX_FLAG_ZERO)) {
				CALLS(I16);
				return 24;
			}
			return 12;

		case 0xEC: // JC #ssss
			I16 = Fetch16();
			if (MinxCPU.F & MINX_FLAG_CARRY) {
				JMPS(I16);
			}
			return 12;
		case 0xED: // JNC #ssss
			I16 = Fetch16();
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) {
				JMPS(I16);
			}
			return 12;
		case 0xEE: // JZ #ssss
			I16 = Fetch16();
			if (MinxCPU.F & MINX_FLAG_ZERO) {
				JMPS(I16);
			}
			return 12;
		case 0xEF: // JNZ #ssss
			I16 = Fetch16();
			if (!(MinxCPU.F & MINX_FLAG_ZERO)) {
				JMPS(I16);
			}
			return 12;

		case 0xF0: // CALL #ss
			I8A = Fetch8();
			CALLS(S8_TO_16(I8A));
			return 20;
		case 0xF1: // JMP #ss
			I8A = Fetch8();
			JMPS(S8_TO_16(I8A));
			return 8;
		case 0xF2: // CALL #ssss
			I16 = Fetch16();
			CALLS(I16);
			return 24;
		case 0xF3: // JMP #ssss
			I16 = Fetch16();
			JMPS(I16);
			return 12;

		case 0xF4: // JMP HL
			JMPU(MinxCPU.HL.W.L);
			return 8;

		case 0xF5: // JDBNZ #ss
			I8A = Fetch8();
			JDBNZ(S8_TO_16(I8A));
			return 16;

		case 0xF6: // SWAP A
			MinxCPU.BA.B.L = SWAP(MinxCPU.BA.B.L);
			return 8;
		case 0xF7: // SWAP [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SWAP(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 12;

		case 0xF8: // RET
			RET();
			return 16;
		case 0xF9: // RETI
			RETI();
			return 16;
		case 0xFA: // RETSKIP
			RET();
			MinxCPU.PC.W.L = MinxCPU.PC.W.L + 2;
			return 16;

		case 0xFB: // CALL [#nnnn]
			I16 = Fetch16();
			CALLX(I16);
			return 20;
		case 0xFC: // CINT #nn
			I16 = Fetch8();
			CALLI(I16);
			return 20;
		case 0xFD: // JINT #nn
			I16 = Fetch8();
			JMPI(I16);
			return 8;

		case 0xFF: // NOP
			return 8;

		case 0xFE: // CRASH
		default:
			break;
	}

	return 4;
}

// Note: Any write to MinxCPU.HL.B.I needs to be reflected into N.B.I

static __attribute__((noinline)) int MinxCPU_ExecCE(void)
{
	uint8_t I8A;
	uint16_t I16;

	// Read IR
	MinxCPU.IR = Fetch8();

	// Process instruction
	switch(MinxCPU.IR) {

		case 0x00: // ADD A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x01: // ADD A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x02: // ADD A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x03: // ADD A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = ADD8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x04: // ADD [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADD8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x05: // ADD [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADD8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x06: // ADD [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADD8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x07: // ADD [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADD8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x08: // ADC A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x09: // ADC A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x0A: // ADC A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x0B: // ADC A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = ADC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x0C: // ADC [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x0D: // ADC [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADC8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x0E: // ADC [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x0F: // ADC [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ADC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x10: // SUB A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x11: // SUB A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x12: // SUB A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x13: // SUB A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x14: // SUB [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x15: // SUB [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x16: // SUB [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x17: // SUB [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x18: // SBC A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x19: // SBC A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x1A: // SBC A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x1B: // SBC A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = SBC8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x1C: // SBC [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SBC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x1D: // SBC [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SBC8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x1E: // SBC [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SBC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x1F: // SBC [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SBC8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x20: // AND A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x21: // AND A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x22: // AND A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x23: // AND A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = AND8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x24: // AND [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, AND8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x25: // AND [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, AND8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x26: // AND [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, AND8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x27: // AND [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, AND8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x28: // OR A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x29: // OR A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x2A: // OR A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x2B: // OR A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = OR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x2C: // OR [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, OR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x2D: // OR [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, OR8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x2E: // OR [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, OR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x2F: // OR [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, OR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x30: // CMP A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x31: // CMP A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x32: // CMP A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x33: // CMP A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			SUB8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x34: // CMP [HL], A
			SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L);
			return 16;
		case 0x35: // CMP [HL], #nn
			I8A = Fetch8();
			SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A);
			return 20;
		case 0x36: // CMP [HL], [X]
			SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D));
			return 20;
		case 0x37: // CMP [HL], [Y]
			SUB8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D));
			return 20;

		case 0x38: // XOR A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x39: // XOR A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;
		case 0x3A: // XOR A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 16;
		case 0x3B: // XOR A, [Y+L]
			I16 = MinxCPU.Y.W.L+ S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = XOR8(MinxCPU.BA.B.L, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 16;

		case 0x3C: // XOR [HL], A
			MinxCPU_OnWrite(1, MinxCPU.HL.D, XOR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU.BA.B.L));
			return 16;
		case 0x3D: // XOR [HL], #nn
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.HL.D, XOR8(MinxCPU_OnRead(1, MinxCPU.HL.D), I8A));
			return 20;
		case 0x3E: // XOR [HL], [X]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, XOR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.X.D)));
			return 20;
		case 0x3F: // XOR [HL], [Y]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, XOR8(MinxCPU_OnRead(1, MinxCPU.HL.D), MinxCPU_OnRead(1, MinxCPU.Y.D)));
			return 20;

		case 0x40: // MOV A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x41: // MOV A, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;
		case 0x42: // MOV A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x43: // MOV A, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;

		case 0x44: // MOV [X+#ss], A
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.BA.B.L);
			return 16;
		case 0x45: // MOV [Y+#ss], A
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.BA.B.L);
			return 16;
		case 0x46: // MOV [X+L], A
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.BA.B.L);
			return 16;
		case 0x47: // MOV [Y+L], A
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.BA.B.L);
			return 16;

		case 0x48: // MOV B, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x49: // MOV B, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;
		case 0x4A: // MOV B, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x4B: // MOV B, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;

		case 0x4C: // MOV [X+#ss], B
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 16;
		case 0x4D: // MOV [Y+#ss], B
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 16;
		case 0x4E: // MOV [X+L], B
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 16;
		case 0x4F: // MOV [Y+L], B
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 16;

		case 0x50: // MOV L, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x51: // MOV L, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;
		case 0x52: // MOV L, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x53: // MOV L, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;

		case 0x54: // MOV [X+#ss], L
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.HL.B.L);
			return 16;
		case 0x55: // MOV [Y+#ss], L
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.HL.B.L);
			return 16;
		case 0x56: // MOV [X+L], L
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.HL.B.L);
			return 16;
		case 0x57: // MOV [Y+L], L
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.HL.B.L);
			return 16;

		case 0x58: // MOV H, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x59: // MOV H, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;
		case 0x5A: // MOV H, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 16;
		case 0x5B: // MOV H, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 16;

		case 0x5C: // MOV [X+#ss], H
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 16;
		case 0x5D: // MOV [Y+#ss], H
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 16;
		case 0x5E: // MOV [X+L], H
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 16;
		case 0x5F: // MOV [Y+L], H
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 16;

		case 0x60: // MOV [HL], [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x61: // MOV [HL], [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;
		case 0x62: // MOV [HL], [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x63: // MOV [HL], [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.HL.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;

		case 0x64: // *ADC BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, I16);
			return 16;
		case 0x65: // *ADC HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, I16);
			return 16;

		case 0x66: // ??? BA, #nn00+L
			I8A = Fetch8();
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, (I8A << 8) | MinxCPU.HL.B.L);
			return 24;
		case 0x67: // ??? HL, #nn00+L
			I8A = Fetch8();
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, (I8A << 8) | MinxCPU.HL.B.L);
			return 24;

		case 0x68: // MOV [X], [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x69: // MOV [X], [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;
		case 0x6A: // MOV [X], [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x6B: // MOV [X], [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.X.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;

		case 0x6C: // *ADD SP, #nnnn
			I16 = Fetch8();
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, I16);

		case 0x6D: // ??? HL, #nn
			I8A = Fetch8();
			MinxCPU.HL.W.L = ADD16(MinxCPU.X.W.L, ((I8A << 4) * 3) + ((I8A & 0x08) >> 3));
			MinxCPU.F &= ~MINX_FLAG_CARRY; // It seems that carry gets clear?
			return 40;
		case 0x6E: // ??? SP, #nn00+L
			I8A = Fetch8();
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, (I8A << 8) | MinxCPU.HL.B.L);
			return 16;
		case 0x6F: // ??? HL, L
			MinxCPU.HL.W.L = ADD16(MinxCPU.X.W.L, ((MinxCPU.HL.B.L << 4) * 3) + ((MinxCPU.HL.B.L & 0x08) >> 3));
			MinxCPU.F &= ~MINX_FLAG_CARRY; // It seems that carry gets clear?
			return 40;

		case 0x70: // NOTHING
			MinxCPU.PC.W.L++;
			return 64;
		case 0x71: // NOTHING
			MinxCPU.PC.W.L++;
			return 64;
		case 0x72: // NOTHING
			return 64;
		case 0x73: // NOTHING
			return 64;

		case 0x74: // *MOV A, [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 64;
		case 0x75: // *MOV L, [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 64;
		case 0x76: // *MOV A, [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 64;
		case 0x77: // *MOV L, [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 64;

		case 0x78: // MOV [Y], [X+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.X.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x79: // MOV [Y], [Y+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.Y.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;
		case 0x7A: // MOV [Y], [X+L]
			I16 = MinxCPU.X.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16));
			return 20;
		case 0x7B: // MOV [Y], [Y+L]
			I16 = MinxCPU.Y.W.L + S8_TO_16(MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, MinxCPU.Y.D, MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16));
			return 20;

		case 0x7C: // NOTHING #nn
			MinxCPU.PC.W.L++;
			return 20;
		case 0x7D: // NOTHING #nn
			MinxCPU.PC.W.L++;
			return 16;
		case 0x7E: // NOTHING
			return 20;
		case 0x7F: // NOTHING
			return 16;

		case 0x80: // SAL A
			MinxCPU.BA.B.L = SAL(MinxCPU.BA.B.L);
			return 12;
		case 0x81: // SAL B
			MinxCPU.BA.B.H = SAL(MinxCPU.BA.B.H);
			return 12;
		case 0x82: // SAL [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, SAL(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x83: // SAL [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SAL(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x84: // SHL A
			MinxCPU.BA.B.L = SHL(MinxCPU.BA.B.L);
			return 12;
		case 0x85: // SHL B
			MinxCPU.BA.B.H = SHL(MinxCPU.BA.B.H);
			return 12;
		case 0x86: // SHL [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, SHL(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x87: // SHL [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SHL(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x88: // SAR A
			MinxCPU.BA.B.L = SAR(MinxCPU.BA.B.L);
			return 12;
		case 0x89: // SAR B
			MinxCPU.BA.B.H = SAR(MinxCPU.BA.B.H);
			return 12;
		case 0x8A: // SAR [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, SAR(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x8B: // SAR [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SAR(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x8C: // SHR A
			MinxCPU.BA.B.L = SHR(MinxCPU.BA.B.L);
			return 12;
		case 0x8D: // SHR B
			MinxCPU.BA.B.H = SHR(MinxCPU.BA.B.H);
			return 12;
		case 0x8E: // SHR [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, SHR(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x8F: // SHR [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, SHR(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x90: // ROLC A
			MinxCPU.BA.B.L = ROLC(MinxCPU.BA.B.L);
			return 12;
		case 0x91: // ROLC B
			MinxCPU.BA.B.H = ROLC(MinxCPU.BA.B.H);
			return 12;
		case 0x92: // ROLC [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, ROLC(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x93: // ROLC [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ROLC(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x94: // ROL A
			MinxCPU.BA.B.L = ROL(MinxCPU.BA.B.L);
			return 12;
		case 0x95: // ROL B
			MinxCPU.BA.B.H = ROL(MinxCPU.BA.B.H);
			return 12;
		case 0x96: // ROL [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, ROL(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x97: // ROL [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ROL(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x98: // RORC A
			MinxCPU.BA.B.L = RORC(MinxCPU.BA.B.L);
			return 12;
		case 0x99: // RORC B
			MinxCPU.BA.B.H = RORC(MinxCPU.BA.B.H);
			return 12;
		case 0x9A: // RORC [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, RORC(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x9B: // RORC [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, RORC(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0x9C: // ROR A
			MinxCPU.BA.B.L = ROR(MinxCPU.BA.B.L);
			return 12;
		case 0x9D: // ROR B
			MinxCPU.BA.B.H = ROR(MinxCPU.BA.B.H);
			return 12;
		case 0x9E: // ROR [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, ROR(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0x9F: // ROR [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, ROR(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0xA0: // NOT A
			MinxCPU.BA.B.L = NOT(MinxCPU.BA.B.L);
			return 12;
		case 0xA1: // NOT B
			MinxCPU.BA.B.H = NOT(MinxCPU.BA.B.H);
			return 12;
		case 0xA2: // NOT [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, NOT(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0xA3: // NOT [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, NOT(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0xA4: // NEG A
			MinxCPU.BA.B.L = NEG(MinxCPU.BA.B.L);
			return 12;
		case 0xA5: // NEG B
			MinxCPU.BA.B.H = NEG(MinxCPU.BA.B.H);
			return 12;
		case 0xA6: // NEG [N+#nn]
			I8A = Fetch8();
			MinxCPU_OnWrite(1, MinxCPU.N.D | I8A, NEG(MinxCPU_OnRead(1, MinxCPU.N.D | I8A)));
			return 20;
		case 0xA7: // NEG [HL]
			MinxCPU_OnWrite(1, MinxCPU.HL.D, NEG(MinxCPU_OnRead(1, MinxCPU.HL.D)));
			return 16;

		case 0xA8: // EX BA, A
			MinxCPU.BA.W.L = S8_TO_16(MinxCPU.BA.B.L);
			return 12;

		case 0xA9: // NOTHING
			return 8;
		case 0xAA: // NOTHING
			return 12;

		case 0xAB: // CRASH
		case 0xAC: // CRASH
		case 0xAD: // CRASH
			return 64;

		case 0xAE: // HALT
			HALT();
			return 8;
		case 0xAF: // STOP
			STOP();
			return 8;

		case 0xB0: // AND B, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.H = AND8(MinxCPU.BA.B.H, I8A);
			return 12;
		case 0xB1: // AND L, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.L = AND8(MinxCPU.HL.B.L, I8A);
			return 12;
		case 0xB2: // AND H, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.H = AND8(MinxCPU.HL.B.H, I8A);
			return 12;
		case 0xB3: // MOV H, V
			MinxCPU.HL.B.H = MinxCPU.PC.B.I;
			return 12;

		case 0xB4: // OR B, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.H = OR8(MinxCPU.BA.B.H, I8A);
			return 12;
		case 0xB5: // OR L, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.L = OR8(MinxCPU.HL.B.L, I8A);
			return 12;
		case 0xB6: // OR H, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.H = OR8(MinxCPU.HL.B.H, I8A);
			return 12;
		case 0xB7: // ??? X
			MinxCPU.X.B.H = MinxCPU.PC.B.I;
			return 12;

		case 0xB8: // XOR B, #nn
			I8A = Fetch8();
			MinxCPU.BA.B.H = XOR8(MinxCPU.BA.B.H, I8A);
			return 12;
		case 0xB9: // XOR L, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.L = XOR8(MinxCPU.HL.B.L, I8A);
			return 12;
		case 0xBA: // XOR H, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.H = XOR8(MinxCPU.HL.B.H, I8A);
			return 12;
		case 0xBB: // ??? Y
			MinxCPU.Y.B.H = MinxCPU.PC.B.I;
			return 12;

		case 0xBC: // CMP B, #nn
			I8A = Fetch8();
			SUB8(MinxCPU.BA.B.H, I8A);
			return 12;
		case 0xBD: // CMP L, #nn
			I8A = Fetch8();
			SUB8(MinxCPU.HL.B.L, I8A);
			return 12;
		case 0xBE: // CMP H, #nn
			I8A = Fetch8();
			SUB8(MinxCPU.HL.B.H, I8A);
			return 12;
		case 0xBF: // CMP N, #nn
			I8A = Fetch8();
			SUB8(MinxCPU.N.B.H, I8A);
			return 12;

		case 0xC0: // MOV A, N
			MinxCPU.BA.B.L = MinxCPU.N.B.H;
			return 8;
		case 0xC1: // MOV A, F
			MinxCPU.BA.B.L = MinxCPU.F;
			return 8;
		case 0xC2: // MOV N, A
			MinxCPU.N.B.H = MinxCPU.BA.B.L;
			return 8;
		case 0xC3: // MOV F, A
			MinxCPU.F = MinxCPU.BA.B.L;
			MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
			return 8;

		case 0xC4: // MOV U, #nn
			I8A = Fetch8();
			Set_U(I8A);
			return 16;
		case 0xC5: // MOV I, #nn
			I8A = Fetch8();
			MinxCPU.HL.B.I = I8A;
			MinxCPU.N.B.I = MinxCPU.HL.B.I;
			return 12;
		case 0xC6: // MOV XI, #nn
			I8A = Fetch8();
			MinxCPU.X.B.I = I8A;
			return 12;
		case 0xC7: // MOV YI, #nn
			I8A = Fetch8();
			MinxCPU.Y.B.I = I8A;
			return 12;

		case 0xC8: // MOV A, V
			MinxCPU.BA.B.L = MinxCPU.PC.B.I;
			return 8;
		case 0xC9: // MOV A, I
			MinxCPU.BA.B.L = MinxCPU.HL.B.I;
			return 8;
		case 0xCA: // MOV A, XI
			MinxCPU.BA.B.L = MinxCPU.X.B.I;
			return 8;
		case 0xCB: // MOV A, YI
			MinxCPU.BA.B.L = MinxCPU.Y.B.I;
			return 8;

		case 0xCC: // MOV U, A
			Set_U(MinxCPU.BA.B.L);
			return 8;
		case 0xCD: // MOV I, A
			MinxCPU.HL.B.I = MinxCPU.BA.B.L;
			MinxCPU.N.B.I = MinxCPU.HL.B.I;
			return 8;
		case 0xCE: // MOV XI, A
			MinxCPU.X.B.I = MinxCPU.BA.B.L;
			return 8;
		case 0xCF: // MOV YI, A
			MinxCPU.Y.B.I = MinxCPU.BA.B.L;
			return 8;

		case 0xD0: // MOV A, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, I16);
			return 20;
		case 0xD1: // MOV B, [#nnnn]
			I16 = Fetch16();
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, I16);
			return 20;
		case 0xD2: // MOV L, [#nnnn]
			I16 = Fetch16();
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, I16);
			return 20;
		case 0xD3: // MOV H, [#nnnn]
			I16 = Fetch16();
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, I16);
			return 20;

		case 0xD4: // MOV [#nnnn], A
			I16 = Fetch16();
			MinxCPU_OnWrite(1, I16, MinxCPU.BA.B.L);
			return 20;
		case 0xD5: // MOV [#nnnn], B
			I16 = Fetch16();
			MinxCPU_OnWrite(1, I16, MinxCPU.BA.B.H);
			return 20;
		case 0xD6: // MOV [#nnnn], L
			I16 = Fetch16();
			MinxCPU_OnWrite(1, I16, MinxCPU.HL.B.L);
			return 20;
		case 0xD7: // MOV [#nnnn], H
			I16 = Fetch16();
			MinxCPU_OnWrite(1, I16, MinxCPU.HL.B.H);
			return 20;

		case 0xD8: // MUL L, A
			MUL();
			return 48;

		case 0xD9: // DIV HL, A
			DIV();
			return 52;

		case 0xDA: // ??? #nn
		case 0xDB: // ??? #nn
			return MinxCPU_ExecSPCE();
		case 0xDC: // CRASH
			return 64;
		case 0xDD: // NOTHING
			return 16;
		case 0xDE: // ??? #nn
		case 0xDF: // ??? #nn
			return MinxCPU_ExecSPCE();

		case 0xE0: // JL #ss
			I8A = Fetch8();
			if ( ((MinxCPU.F & MINX_FLAG_OVERFLOW)!=0) != ((MinxCPU.F & MINX_FLAG_SIGN)!=0) ) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE1: // JLE #ss
			I8A = Fetch8();
			if ( (((MinxCPU.F & MINX_FLAG_OVERFLOW)==0) != ((MinxCPU.F & MINX_FLAG_SIGN)==0)) || ((MinxCPU.F & MINX_FLAG_ZERO)!=0) ) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE2: // JG #ss
			I8A = Fetch8();
			if ( (((MinxCPU.F & MINX_FLAG_OVERFLOW)!=0) == ((MinxCPU.F & MINX_FLAG_SIGN)!=0)) && ((MinxCPU.F & MINX_FLAG_ZERO)==0) ) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE3: // JGE #ss
			I8A = Fetch8();
			if ( ((MinxCPU.F & MINX_FLAG_OVERFLOW)==0) == ((MinxCPU.F & MINX_FLAG_SIGN)==0) ) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;

		case 0xE4: // JO #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_OVERFLOW) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE5: // JNO #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_OVERFLOW)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE6: // JP #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_SIGN)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE7: // JNP #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_SIGN) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;

		case 0xE8: // JNX0 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x01)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xE9: // JNX1 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x02)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xEA: // JNX2 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x04)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xEB: // JNX3 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x08)) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;

		case 0xEC: // JX0 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x01) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xED: // JX1 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x02) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xEE: // JX2 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x04) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;
		case 0xEF: // JX3 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x08) {
				JMPS(S8_TO_16(I8A));
			}
			return 12;

		case 0xF0: // CALLL #ss
			I8A = Fetch8();
			if ( ((MinxCPU.F & MINX_FLAG_OVERFLOW)!=0) != ((MinxCPU.F & MINX_FLAG_SIGN)!=0) ) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF1: // CALLLE #ss
			I8A = Fetch8();
			if ( (((MinxCPU.F & MINX_FLAG_OVERFLOW)==0) != ((MinxCPU.F & MINX_FLAG_SIGN)==0)) || ((MinxCPU.F & MINX_FLAG_ZERO)!=0) ) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF2: // CALLG #ss
			I8A = Fetch8();
			if ( (((MinxCPU.F & MINX_FLAG_OVERFLOW)!=0) == ((MinxCPU.F & MINX_FLAG_SIGN)!=0)) && ((MinxCPU.F & MINX_FLAG_ZERO)==0) ) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF3: // CALLGE #ss
			I8A = Fetch8();
			if ( ((MinxCPU.F & MINX_FLAG_OVERFLOW)==0) == ((MinxCPU.F & MINX_FLAG_SIGN)==0) ) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;

		case 0xF4: // CALLO #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_OVERFLOW) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF5: // CALLNO #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_OVERFLOW)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF6: // CALLNS #ss
			I8A = Fetch8();
			if (!(MinxCPU.F & MINX_FLAG_SIGN)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF7: // CALLS #ss
			I8A = Fetch8();
			if (MinxCPU.F & MINX_FLAG_SIGN) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;

		case 0xF8: // CALLNX0 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x01)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xF9: // CALLNX1 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x02)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xFA: // CALLNX2 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x04)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xFB: // CALLNX3 #ss
			I8A = Fetch8();
			if (!(MinxCPU.E & 0x08)) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;

		case 0xFC: // CALLX0 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x01) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xFD: // CALLX1 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x02) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xFE: // CALLX2 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x04) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;
		case 0xFF: // CALLX3 #ss
			I8A = Fetch8();
			if (MinxCPU.E & 0x08) {
				CALLS(S8_TO_16(I8A));
			}
			return 12;

		default:
			break;
	}

	return 4;
}

// Note: Any write to MinxCPU.HL.B.I needs to be reflected into MinxCPU.N.B.I

static __attribute__((noinline)) int MinxCPU_ExecCF(void)
{
	uint8_t I8A;
	uint16_t I16;

	// Read IR
	MinxCPU.IR = Fetch8();

	// Process instruction
	switch(MinxCPU.IR) {
		case 0x00: // ADD BA, BA
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x01: // ADD BA, HL
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x02: // ADD BA, X
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x03: // ADD BA, Y
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x04: // ADC BA, BA
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x05: // ADC BA, HL
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x06: // ADC BA, X
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x07: // ADC BA, Y
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x08: // SUB BA, BA
			MinxCPU.BA.W.L = SUB16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x09: // SUB BA, HL
			MinxCPU.BA.W.L = SUB16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x0A: // SUB BA, X
			MinxCPU.BA.W.L = SUB16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x0B: // SUB BA, Y
			MinxCPU.BA.W.L = SUB16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x0C: // SBC BA, BA
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x0D: // SBC BA, HL
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x0E: // SBC BA, X
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x0F: // SBC BA, Y
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x10: // *ADD BA, BA
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x11: // *ADD BA, HL
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x12: // *ADD BA, X
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x13: // *ADD BA, Y
			MinxCPU.BA.W.L = ADD16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x14: // *ADC BA, BA
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x15: // *ADC BA, HL
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x16: // *ADC BA, X
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x17: // *ADC BA, Y
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x18: // CMP BA, BA
			SUB16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x19: // CMP BA, HL
			SUB16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x1A: // CMP BA, X
			SUB16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x1B: // CMP BA, Y
			SUB16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x1C: // *SBC BA, BA
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x1D: // *SBC BA, HL
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x1E: // *SBC BA, X
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x1F: // *SBC BA, Y
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x20: // ADD HL, BA
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x21: // ADD HL, HL
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x22: // ADD HL, X
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x23: // ADD HL, Y
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x24: // ADC HL, BA
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x25: // ADC HL, HL
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x26: // ADC HL, X
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x27: // ADC HL, Y
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x28: // SUB HL, BA
			MinxCPU.HL.W.L = SUB16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x29: // SUB HL, HL
			MinxCPU.HL.W.L = SUB16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x2A: // SUB HL, X
			MinxCPU.HL.W.L = SUB16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x2B: // SUB HL, Y
			MinxCPU.HL.W.L = SUB16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x2C: // SBC HL, BA
			MinxCPU.HL.W.L = SBC16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x2D: // SBC HL, HL
			MinxCPU.HL.W.L = SBC16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x2E: // SBC HL, X
			MinxCPU.HL.W.L = SBC16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x2F: // SBC HL, Y
			MinxCPU.HL.W.L = SBC16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x30: // *ADD HL, BA
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x31: // *ADD BA, HL
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x32: // *ADD BA, X
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x33: // *ADD BA, Y
			MinxCPU.HL.W.L = ADD16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x34: // *ADC HL, BA
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x35: // *ADC HL, HL
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x36: // *ADC HL, X
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x37: // *ADC HL, Y
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x38: // CMP HL, BA
			SUB16(MinxCPU.HL.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x39: // CMP HL, HL
			SUB16(MinxCPU.HL.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x3A: // CMP HL, X
			SUB16(MinxCPU.HL.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x3B: // CMP HL, Y
			SUB16(MinxCPU.HL.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x3C: // *SBC BA, BA
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x3D: // *SBC BA, HL
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x3E: // *SBC BA, X
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.X.W.L);
			return 16;
		case 0x3F: // *SBC BA, Y
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, MinxCPU.Y.W.L);
			return 16;

		case 0x40: // ADD X, BA
			MinxCPU.X.W.L = ADD16(MinxCPU.X.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x41: // ADD X, HL
			MinxCPU.X.W.L = ADD16(MinxCPU.X.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x42: // ADD Y, BA
			MinxCPU.Y.W.L = ADD16(MinxCPU.Y.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x43: // ADD Y, HL
			MinxCPU.Y.W.L = ADD16(MinxCPU.Y.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x44: // ADD SP, BA
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x45: // ADD SP, HL
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x46: // CRASH
		case 0x47: // CRASH
			return 16;

		case 0x48: // SUB X, BA
			MinxCPU.X.W.L = SUB16(MinxCPU.X.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x49: // SUB X, HL
			MinxCPU.X.W.L = SUB16(MinxCPU.X.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x4A: // SUB Y, BA
			MinxCPU.Y.W.L = SUB16(MinxCPU.Y.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x4B: // SUB Y, HL
			MinxCPU.Y.W.L = SUB16(MinxCPU.Y.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x4C: // SUB SP, BA
			MinxCPU.SP.W.L = SUB16(MinxCPU.SP.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x4D: // SUB SP, HL
			MinxCPU.SP.W.L = SUB16(MinxCPU.SP.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x4E: // CRASH
		case 0x4F: // CRASH
			return 16;

		case 0x50: // *ADD X, BA
			MinxCPU.X.W.L = ADD16(MinxCPU.X.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x51: // *ADD X, HL
			MinxCPU.X.W.L = ADD16(MinxCPU.X.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x52: // *ADD Y, BA
			MinxCPU.Y.W.L = ADD16(MinxCPU.Y.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x53: // *ADD Y, HL
			MinxCPU.Y.W.L = ADD16(MinxCPU.Y.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x54: // *ADD SP, BA
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x55: // *ADD SP, HL
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x56: // CRASH
		case 0x57: // CRASH
			return 16;

		case 0x58: // *SUB X, BA
			MinxCPU.X.W.L = SUB16(MinxCPU.X.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x59: // *SUB X, HL
			MinxCPU.X.W.L = SUB16(MinxCPU.X.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x5A: // *SUB Y, BA
			MinxCPU.Y.W.L = SUB16(MinxCPU.Y.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x5B: // *SUB Y, HL
			MinxCPU.Y.W.L = SUB16(MinxCPU.Y.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x5C: // CMP SP, BA
			SUB16(MinxCPU.SP.W.L, MinxCPU.BA.W.L);
			return 16;
		case 0x5D: // CMP SP, HL
			SUB16(MinxCPU.SP.W.L, MinxCPU.HL.W.L);
			return 16;
		case 0x5E: // CRASH
		case 0x5F: // CRASH
			return 16;

		case 0x60: // ADC BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = ADC16(MinxCPU.BA.W.L, I16);
			return 16;
		case 0x61: // ADC HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = ADC16(MinxCPU.HL.W.L, I16);
			return 16;
		case 0x62: // SBC BA, #nnnn
			I16 = Fetch16();
			MinxCPU.BA.W.L = SBC16(MinxCPU.BA.W.L, I16);
			return 16;
		case 0x63: // SBC HL, #nnnn
			I16 = Fetch16();
			MinxCPU.HL.W.L = SBC16(MinxCPU.HL.W.L, I16);
			return 16;

		case 0x64: // UNSTABLE
		case 0x65: // UNSTABLE
		case 0x66: // UNSTABLE
		case 0x67: // UNSTABLE
			return 16;

		case 0x68: // ADD SP, #nnnn
			I16 = Fetch16();
			MinxCPU.SP.W.L = ADD16(MinxCPU.SP.W.L, I16);
			return 16;

		case 0x6A: // SUB SP, #nnnn
			I16 = Fetch16();
			MinxCPU.SP.W.L = SUB16(MinxCPU.SP.W.L, I16);
			return 16;
		case 0x69: // UNSTABLE
		case 0x6B: // UNSTABLE
		case 0x6D: // UNSTABLE
		case 0x6F: // UNSTABLE
			return 16;

		case 0x6C: // CMP SP, #nnnn
			I16 = Fetch16();
			SUB16(MinxCPU.SP.W.L, I16);
			return 16;

		case 0x6E: // MOV SP, #nnnn
			I16 = Fetch16();
			MinxCPU.SP.W.L = I16;
			return 16;

		case 0x70: // MOV BA, [SP+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, I16++);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, I16);
			return 24;
		case 0x71: // MOV HL, [SP+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, I16++);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, I16);
			return 24;
		case 0x72: // MOV X, [SP+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU.X.B.L = MinxCPU_OnRead(1, I16++);
			MinxCPU.X.B.H = MinxCPU_OnRead(1, I16);
			return 24;
		case 0x73: // MOV Y, [SP+#ss]
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU.Y.B.L = MinxCPU_OnRead(1, I16++);
			MinxCPU.Y.B.H = MinxCPU_OnRead(1, I16);
			return 24;

		case 0x74: // MOV [SP+#ss], BA
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, I16++, MinxCPU.BA.B.L);
			MinxCPU_OnWrite(1, I16, MinxCPU.BA.B.H);
			return 24;
		case 0x75: // MOV [SP+#ss], HL
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, I16++, MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, I16, MinxCPU.HL.B.H);
			return 24;
		case 0x76: // MOV [SP+#ss], X
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, I16++, MinxCPU.X.B.L);
			MinxCPU_OnWrite(1, I16, MinxCPU.X.B.H);
			return 24;
		case 0x77: // MOV [SP+#ss], Y
			I8A = Fetch8();
			I16 = MinxCPU.SP.W.L + S8_TO_16(I8A);
			MinxCPU_OnWrite(1, I16++, MinxCPU.Y.B.L);
			MinxCPU_OnWrite(1, I16, MinxCPU.Y.B.H);
			return 24;

		case 0x78: // MOV SP, [#nnnn]
			I16 = Fetch16();
			MinxCPU.SP.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.SP.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 24;

		case 0x79: // ??? #nn
		case 0x7A: // ??? #nn
		case 0x7B: // ??? #nn
			return MinxCPU_ExecSPCF();

		case 0x7C: // MOV [#nnnn], SP
			I16 = Fetch16();
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.SP.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.SP.B.H);
			return 24;

		case 0x7D: case 0x7E: case 0x7F: // ??? #nn
		case 0x80: case 0x81: case 0x82: case 0x83:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
		case 0x90: case 0x91: case 0x92: case 0x93:
		case 0x94: case 0x95: case 0x96: case 0x97:
		case 0x98: case 0x99: case 0x9A: case 0x9B:
		case 0x9C: case 0x9D: case 0x9E: case 0x9F:
		case 0xA0: case 0xA1: case 0xA2: case 0xA3:
		case 0xA4: case 0xA5: case 0xA6: case 0xA7:
		case 0xA8: case 0xA9: case 0xAA: case 0xAB:
		case 0xAC: case 0xAD: case 0xAE: case 0xAF:
			return MinxCPU_ExecSPCF();

		case 0xB0: // PUSH A
			PUSH(MinxCPU.BA.B.L);
			return 12;
		case 0xB1: // PUSH B
			PUSH(MinxCPU.BA.B.H);
			return 12;
		case 0xB2: // PUSH L
			PUSH(MinxCPU.HL.B.L);
			return 12;
		case 0xB3: // PUSH H
			PUSH(MinxCPU.HL.B.H);
			return 12;

		case 0xB4: // POP A
			MinxCPU.BA.B.L = POP();
			return 12;
		case 0xB5: // POP B
			MinxCPU.BA.B.H = POP();
			return 12;
		case 0xB6: // POP L
			MinxCPU.HL.B.L = POP();
			return 12;
		case 0xB7: // POP H
			MinxCPU.HL.B.H = POP();
			return 12;
		case 0xB8: // PUSHA
			PUSH(MinxCPU.BA.B.H);
			PUSH(MinxCPU.BA.B.L);
			PUSH(MinxCPU.HL.B.H);
			PUSH(MinxCPU.HL.B.L);
			PUSH(MinxCPU.X.B.H);
			PUSH(MinxCPU.X.B.L);
			PUSH(MinxCPU.Y.B.H);
			PUSH(MinxCPU.Y.B.L);
			PUSH(MinxCPU.N.B.H);
			return 48;
		case 0xB9: // PUSHAX
			PUSH(MinxCPU.BA.B.H);
			PUSH(MinxCPU.BA.B.L);
			PUSH(MinxCPU.HL.B.H);
			PUSH(MinxCPU.HL.B.L);
			PUSH(MinxCPU.X.B.H);
			PUSH(MinxCPU.X.B.L);
			PUSH(MinxCPU.Y.B.H);
			PUSH(MinxCPU.Y.B.L);
			PUSH(MinxCPU.N.B.H);
			PUSH(MinxCPU.HL.B.I);
			PUSH(MinxCPU.X.B.I);
			PUSH(MinxCPU.Y.B.I);
			return 60;

		case 0xBA: case 0xBB: // ??? #n
			return MinxCPU_ExecSPCF();

		case 0xBC: // POPA
			MinxCPU.N.B.H = POP();
			MinxCPU.Y.B.L = POP();
			MinxCPU.Y.B.H = POP();
			MinxCPU.X.B.L = POP();
			MinxCPU.X.B.H = POP();
			MinxCPU.HL.B.L = POP();
			MinxCPU.HL.B.H = POP();
			MinxCPU.BA.B.L = POP();
			MinxCPU.BA.B.H = POP();
			return 44;

		case 0xBD: // POPAX
			MinxCPU.Y.B.I = POP();
			MinxCPU.X.B.I = POP();
			MinxCPU.HL.B.I = POP();
			MinxCPU.N.B.I = MinxCPU.HL.B.I;
			MinxCPU.N.B.H = POP();
			MinxCPU.Y.B.L = POP();
			MinxCPU.Y.B.H = POP();
			MinxCPU.X.B.L = POP();
			MinxCPU.X.B.H = POP();
			MinxCPU.HL.B.L = POP();
			MinxCPU.HL.B.H = POP();
			MinxCPU.BA.B.L = POP();
			MinxCPU.BA.B.H = POP();
			return 56;

		case 0xBE: case 0xBF: // ??? #n
			return MinxCPU_ExecSPCF();

		case 0xC0: // MOV BA, [HL]
			I16 = MinxCPU.HL.W.L;
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xC1: // MOV HL, [HL]
			I16 = MinxCPU.HL.W.L;
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xC2: // MOV X, [HL]
			I16 = MinxCPU.HL.W.L;
			MinxCPU.X.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.X.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;
		case 0xC3: // MOV Y, [HL]
			I16 = MinxCPU.HL.W.L;
			MinxCPU.Y.B.L = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16++);
			MinxCPU.Y.B.H = MinxCPU_OnRead(1, (MinxCPU.HL.B.I << 16) | I16);
			return 20;

		case 0xC4: // MOV [HL], BA
			I16 = MinxCPU.HL.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.BA.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 20;
		case 0xC5: // MOV [HL], HL
			I16 = MinxCPU.HL.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 20;
		case 0xC6: // MOV [HL], X
			I16 = MinxCPU.HL.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.X.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.X.B.H);
			return 20;
		case 0xC7: // MOV [HL], Y
			I16 = MinxCPU.HL.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16++, MinxCPU.Y.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.HL.B.I << 16) | I16, MinxCPU.Y.B.H);
			return 20;

		case 0xC8: case 0xC9: case 0xCA: case 0xCB: // MOV B, V
		case 0xCC: case 0xCD: case 0xCE: case 0xCF:
			MinxCPU.BA.B.H = MinxCPU.PC.B.I;
			return 12;

		case 0xD0: // MOV BA, [X]
			I16 = MinxCPU.X.W.L;
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16++);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 20;
		case 0xD1: // MOV HL, [X]
			I16 = MinxCPU.X.W.L;
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16++);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 20;
		case 0xD2: // MOV X, [X]
			I16 = MinxCPU.X.W.L;
			MinxCPU.X.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16++);
			MinxCPU.X.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 20;
		case 0xD3: // MOV Y, [X]
			I16 = MinxCPU.X.W.L;
			MinxCPU.Y.B.L = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16++);
			MinxCPU.Y.B.H = MinxCPU_OnRead(1, (MinxCPU.X.B.I << 16) | I16);
			return 20;

		case 0xD4: // MOV [X], BA
			I16 = MinxCPU.X.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16++, MinxCPU.BA.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 20;
		case 0xD5: // MOV [X], HL
			I16 = MinxCPU.X.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16++, MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 20;
		case 0xD6: // MOV [X], X
			I16 = MinxCPU.X.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16++, MinxCPU.X.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.X.B.H);
			return 20;
		case 0xD7: // MOV [X], Y
			I16 = MinxCPU.X.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16++, MinxCPU.Y.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.X.B.I << 16) | I16, MinxCPU.Y.B.H);
			return 20;

		case 0xD8: // MOV BA, [Y]
			I16 = MinxCPU.Y.W.L;
			MinxCPU.BA.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16++);
			MinxCPU.BA.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 20;
		case 0xD9: // MOV HL, [Y]
			I16 = MinxCPU.Y.W.L;
			MinxCPU.HL.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16++);
			MinxCPU.HL.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 20;
		case 0xDA: // MOV X, [Y]
			I16 = MinxCPU.Y.W.L;
			MinxCPU.X.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16++);
			MinxCPU.X.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 20;
		case 0xDB: // MOV Y, [Y]
			I16 = MinxCPU.Y.W.L;
			MinxCPU.Y.B.L = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16++);
			MinxCPU.Y.B.H = MinxCPU_OnRead(1, (MinxCPU.Y.B.I << 16) | I16);
			return 20;

		case 0xDC: // MOV [Y], BA
			I16 = MinxCPU.Y.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16++, MinxCPU.BA.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.BA.B.H);
			return 20;
		case 0xDD: // MOV [Y], HL
			I16 = MinxCPU.Y.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16++, MinxCPU.HL.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.HL.B.H);
			return 20;
		case 0xDE: // MOV [Y], X
			I16 = MinxCPU.Y.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16++, MinxCPU.X.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.X.B.H);
			return 20;
		case 0xDF: // MOV [Y], Y
			I16 = MinxCPU.Y.W.L;
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16++, MinxCPU.Y.B.L);
			MinxCPU_OnWrite(1, (MinxCPU.Y.B.I << 16) | I16, MinxCPU.Y.B.H);
			return 20;

		case 0xE0: // MOV BA, BA
			return 8;
		case 0xE1: // MOV BA, HL
			MinxCPU.BA.W.L = MinxCPU.HL.W.L;
			return 8;
		case 0xE2: // MOV BA, X
			MinxCPU.BA.W.L = MinxCPU.X.W.L;
			return 8;
		case 0xE3: // MOV BA, Y
			MinxCPU.BA.W.L = MinxCPU.Y.W.L;
			return 8;

		case 0xE4: // MOV HL, BA
			MinxCPU.HL.W.L = MinxCPU.BA.W.L;
			return 8;
		case 0xE5: // MOV HL, HL
			return 8;
		case 0xE6: // MOV HL, X
			MinxCPU.HL.W.L = MinxCPU.X.W.L;
			return 8;
		case 0xE7: // MOV HL, Y
			MinxCPU.HL.W.L = MinxCPU.Y.W.L;
			return 8;

		case 0xE8: // MOV X, BA
			MinxCPU.X.W.L = MinxCPU.BA.W.L;
			return 8;
		case 0xE9: // MOV X, HL
			MinxCPU.X.W.L = MinxCPU.HL.W.L;
			return 8;
		case 0xEA: // MOV X, X
			return 8;
		case 0xEB: // MOV X, Y
			MinxCPU.X.W.L = MinxCPU.Y.W.L;
			return 8;

		case 0xEC: // MOV Y, BA
			MinxCPU.Y.W.L = MinxCPU.BA.W.L;
			return 8;
		case 0xED: // MOV Y, HL
			MinxCPU.Y.W.L = MinxCPU.HL.W.L;
			return 8;
		case 0xEE: // MOV Y, X
			MinxCPU.Y.W.L = MinxCPU.X.W.L;
			return 8;
		case 0xEF: // MOV Y, Y
			return 8;

		case 0xF0: // MOV SP, BA
			MinxCPU.SP.W.L = MinxCPU.BA.W.L;
			return 8;
		case 0xF1: // MOV SP, HL
			MinxCPU.SP.W.L = MinxCPU.HL.W.L;
			return 8;
		case 0xF2: // MOV SP, X
			MinxCPU.SP.W.L = MinxCPU.X.W.L;
			return 8;
		case 0xF3: // MOV SP, Y
			MinxCPU.SP.W.L = MinxCPU.Y.W.L;
			return 8;

		case 0xF4: // MOV HL, SP
			MinxCPU.HL.W.L = MinxCPU.SP.W.L;
			return 8;
		case 0xF5: // MOV HL, PC
			MinxCPU.HL.W.L = MinxCPU.PC.W.L;
			return 8;
		case 0xF6: // ??? X
			MinxCPU.X.B.H = MinxCPU.PC.B.I;
			return 12;
		case 0xF7: // ??? Y
			MinxCPU.Y.B.H = MinxCPU.PC.B.I;
			return 12;

		case 0xF8: // MOV BA, SP
			MinxCPU.BA.W.L = MinxCPU.SP.W.L;
			return 8;
		case 0xF9: // MOV BA, PC
			MinxCPU.BA.W.L = MinxCPU.PC.W.L;
			return 8;

		case 0xFA: // MOV X, SP
			MinxCPU.X.W.L = MinxCPU.SP.W.L;
			return 8;

		case 0xFB: // NOTHING
		case 0xFC: // NOTHING
			return 12;
		case 0xFD: // MOV A, E
			MinxCPU.BA.B.L = MinxCPU.E;
			return 12;

		case 0xFE: // MOV Y, SP
			MinxCPU.Y.W.L = MinxCPU.SP.W.L;
			return 8;

		case 0xFF: // NOTHING
			return 64;

		default:
			break;
	}

	return 4;
}

static __attribute__((noinline)) int MinxCPU_ExecSPCE(void)
{
	// Read IR
	MinxCPU.IR = Fetch8();

	return 64;
}

static __attribute__((noinline)) int MinxCPU_ExecSPCF(void)
{
	// Read IR
	MinxCPU.IR = Fetch8();

	// Process instruction
	switch(MinxCPU.IR) {
		case 0x00: case 0x01: case 0x02: case 0x03: // Decrement BA
			MinxCPU.BA.W.L = DEC16(MinxCPU.BA.W.L);
			return 16;
		case 0x04: case 0x05: case 0x06: case 0x07: // Decrement BA if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.BA.W.L = DEC16(MinxCPU.BA.W.L);
			return 16;
		case 0x08: case 0x09: case 0x0A: case 0x0B: // Increment BA
			MinxCPU.BA.W.L = INC16(MinxCPU.BA.W.L);
			return 16;
		case 0x0C: case 0x0D: case 0x0E: case 0x0F: // Increment BA if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.BA.W.L = INC16(MinxCPU.BA.W.L);
			return 16;
		case 0x10: case 0x11: case 0x12: case 0x13: // Decrement BA
			MinxCPU.BA.W.L = DEC16(MinxCPU.BA.W.L);
			return 16;
		case 0x14: case 0x15: case 0x16: case 0x17: // Decrement BA if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.BA.W.L = DEC16(MinxCPU.BA.W.L);
			return 16;
		case 0x18: case 0x19: case 0x1A: case 0x1B: // Increment BA (Doesn't save result!!)
			INC16(MinxCPU.BA.W.L);
			return 16;
		case 0x1C: case 0x1D: case 0x1E: case 0x1F: // Increment BA if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.BA.W.L = INC16(MinxCPU.BA.W.L);
			return 16;

		case 0x20: case 0x21: case 0x22: case 0x23: // Decrement HL
			MinxCPU.HL.W.L = DEC16(MinxCPU.HL.W.L);
			return 16;
		case 0x24: case 0x25: case 0x26: case 0x27: // Decrement HL if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.HL.W.L = DEC16(MinxCPU.HL.W.L);
			return 16;
		case 0x28: case 0x29: case 0x2A: case 0x2B: // Increment HL
			MinxCPU.HL.W.L = INC16(MinxCPU.HL.W.L);
			return 16;
		case 0x2C: case 0x2D: case 0x2E: case 0x2F: // Increment HL if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.HL.W.L = INC16(MinxCPU.HL.W.L);
			return 16;
		case 0x30: case 0x31: case 0x32: case 0x33: // Decrement HL
			MinxCPU.HL.W.L = DEC16(MinxCPU.HL.W.L);
			return 16;
		case 0x34: case 0x35: case 0x36: case 0x37: // Decrement HL if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.HL.W.L = DEC16(MinxCPU.HL.W.L);
			return 16;
		case 0x38: case 0x39: case 0x3A: case 0x3B: // Increment HL (Doesn't save result!!)
			INC16(MinxCPU.HL.W.L);
			return 16;
		case 0x3C: case 0x3D: case 0x3E: case 0x3F: // Increment HL if Carry = 0
			if (!(MinxCPU.F & MINX_FLAG_CARRY)) MinxCPU.HL.W.L = INC16(MinxCPU.HL.W.L);
			return 16;

		case 0x40: case 0x41: // Decrement X
			MinxCPU.X.W.L = DEC16(MinxCPU.X.W.L);
			return 16;
		case 0x42: case 0x43: // Decrement Y
			MinxCPU.X.W.L = DEC16(MinxCPU.X.W.L);
			return 16;
		case 0x44: case 0x45: // Decrement SP
			MinxCPU.SP.W.L = DEC16(MinxCPU.SP.W.L);
			return 16;
		case 0x46: case 0x47: // CRASH
			return 16;

		case 0x48: case 0x49: // Increment X
			MinxCPU.X.W.L = INC16(MinxCPU.X.W.L);
			return 16;
		case 0x4A: case 0x4B: // Increment Y
			MinxCPU.X.W.L = INC16(MinxCPU.X.W.L);
			return 16;
		case 0x4C: case 0x4D: // Increment SP
			MinxCPU.SP.W.L = INC16(MinxCPU.SP.W.L);
			return 16;
		case 0x4E: case 0x4F: // CRASH
		case 0x56: case 0x57: // CRASH
		case 0x5E: case 0x5F: // CRASH
		case 0x60: case 0x61: case 0x62: case 0x63: // CRASH
		case 0x64: case 0x65: case 0x66: case 0x67:
		case 0x68: case 0x69: case 0x6A: case 0x6B:
		case 0x6C: case 0x6D: case 0x6E: case 0x6F:
			return 16;

		case 0x50: case 0x51: // Decrement X
			MinxCPU.X.W.L = DEC16(MinxCPU.X.W.L);
			return 16;
		case 0x52: case 0x53: // Decrement Y
			MinxCPU.X.W.L = DEC16(MinxCPU.X.W.L);
			return 16;
		case 0x54: case 0x55: // Decrement SP
			MinxCPU.SP.W.L = DEC16(MinxCPU.SP.W.L);
			return 16;

		case 0x58: case 0x59: // Increment X
			MinxCPU.X.W.L = INC16(MinxCPU.X.W.L);
			return 16;
		case 0x5A: case 0x5B: // Increment Y
			MinxCPU.X.W.L = INC16(MinxCPU.X.W.L);
			return 16;
		case 0x5C: case 0x5D: // Increment SP
			MinxCPU.SP.W.L = INC16(MinxCPU.SP.W.L);
			return 16;


		case 0x70: // BA = (0x4D << 8) | V
			MinxCPU.BA.W.L = 0x4D00 | MinxCPU.PC.B.I;
			return 24;
		case 0x71: // HL = (0x4D << 8) | V
			MinxCPU.HL.W.L = 0x4D00 | MinxCPU.PC.B.I;
			return 24;
		case 0x72: // X = (0x4D << 8) | V
			MinxCPU.X.W.L = 0x4D00 | MinxCPU.PC.B.I;
			return 24;
		case 0x73: // Y = (0x4D << 8) | V
			MinxCPU.Y.W.L = 0x4D00 | MinxCPU.PC.B.I;
			return 24;

		case 0x74: case 0x75: case 0x76: case 0x77: // NOTHING
			return 24;

		case 0x78: case 0x79: case 0x7A: case 0x7B: // CRASH
		case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		case 0x80: case 0x81: case 0x82: case 0x83:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
		case 0x90: case 0x91: case 0x92: case 0x93:
		case 0x94: case 0x95: case 0x96: case 0x97:
		case 0x98: case 0x99: case 0x9A: case 0x9B:
		case 0x9C: case 0x9D: case 0x9E: case 0x9F:
		case 0xA0: case 0xA1: case 0xA2: case 0xA3:
		case 0xA4: case 0xA5: case 0xA6: case 0xA7:
		case 0xA8: case 0xA9: case 0xAA: case 0xAB:
		case 0xAC: case 0xAD: case 0xAE: case 0xAF:
			return 24;

		case 0xB0: case 0xB1: case 0xB2: case 0xB3: // NOTHING
			return 12;

		case 0xB4: case 0xB5: case 0xB6: case 0xB7: // CRASH
		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
			return 12;

		case 0xC0: // BA = (0x20 << 8) | V
			MinxCPU.BA.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xC1: // HL = (0x20 << 8) | V
			MinxCPU.HL.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xC2: // X = (0x20 << 8) | V
			MinxCPU.X.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xC3: // Y = (0x20 << 8) | V
			MinxCPU.Y.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;

		case 0xC4: case 0xC5: case 0xC6: case 0xC7: // NOTHING
			return 20;

		case 0xC8: case 0xC9: case 0xCA: case 0xCB: // CRASH
		case 0xCC: case 0xCD: case 0xCE: case 0xCF:
			return 20;

		case 0xD0: // BA = (0x20 << 8) | V
			MinxCPU.BA.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xD1: // HL = (0x20 << 8) | V
			MinxCPU.HL.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xD2: // X = (0x20 << 8) | V
			MinxCPU.X.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xD3: // Y = (0x00 << 8) | V ? (EH!?)
			MinxCPU.Y.W.L = 0x0000 | MinxCPU.PC.B.I;
			return 20;

		case 0xD4: case 0xD5: case 0xD6: case 0xD7: // NOTHING
			return 20;

		case 0xD8: // BA = (0x20 << 8) | V
			MinxCPU.BA.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xD9: // HL = (0x20 << 8) | V
			MinxCPU.HL.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xDA: // X = (0x20 << 8) | V
			MinxCPU.X.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;
		case 0xDB: // Y = (0x20 << 8) | V
			MinxCPU.Y.W.L = 0x2000 | MinxCPU.PC.B.I;
			return 20;

		case 0xDC: case 0xDD: case 0xDE: case 0xDF: // NOTHING
			return 20;
		
		case 0xE0: case 0xE1: case 0xE2: case 0xE3: // CRASH
		case 0xE4: case 0xE5: case 0xE6: case 0xE7:
		case 0xE8: case 0xE9: case 0xEA: case 0xEB:
		case 0xEC: case 0xED: case 0xEE: case 0xEF:
		case 0xF0: case 0xF1: case 0xF2: case 0xF3:
		case 0xF4: case 0xF5: case 0xF6: case 0xF7:
		case 0xF8: case 0xF9: case 0xFA: case 0xFB:
		case 0xFC: case 0xFD: case 0xFE: case 0xFF:
			return 24;

		default:
			break;
	}

	return 64;
}


#define RGB15_PM(r, g, b) ((u16)((((r) >> 3) & 31) | ((((g) >> 3) & 31) << 5) | ((((b) >> 3) & 31) << 10)))

static void build_lcd_palette(void)
{
    for (int i = 0; i < 256; i++) {
        int inv = 255 - i;
        int curve = 255 - ((inv * inv * inv) >> 16);
        int t = (i * 180 + curve * 76) >> 8;
        int r = (0xB4 * (255 - t) + 0x14 * t) >> 8;
        int g = (0xC8 * (255 - t) + 0x1E * t) >> 8;
        int b = (0xA0 * (255 - t) + 0x10 * t) >> 8;
        WS->lcd_pal[i] = RGB15_PM(r, g, b);
    }
}

static void pm_set_keys(u16 pad, const u8 *hid, int hid_n)
{
    uint8_t mask = 0;
    int shock = 0;

    if (pad & 0x01u)  mask |= 0x01u;    /* A */
    if (pad & 0x02u)  mask |= 0x02u;    /* B */
    if (pad & 0x08u)  mask |= 0x04u;    /* START -> C */
    if (pad & 0x200u) mask |= 0x04u;    /* R -> C */
    if (pad & 0x10u)  mask |= 0x08u;    /* UP */
    if (pad & 0x20u)  mask |= 0x10u;    /* DOWN */
    if (pad & 0x40u)  mask |= 0x20u;    /* LEFT */
    if (pad & 0x80u)  mask |= 0x40u;    /* RIGHT */
    if (pad & 0x04u)  mask |= 0x80u;    /* SELECT -> Power */
    if (pad & 0x100u) shock = 1;        /* L -> Shock */

    for (int i = 0; i < hid_n; i++) {
        switch (hid[i]) {
        case 0x06: case 0x08: mask |= 0x04u; break; /* C / E -> C button */
        case 0x14: case 0x2C: shock = 1; break;     /* Q / Space -> Shake / Shock */
        case 0x13: case 0x3A: mask |= 0x80u; break; /* P / F1 -> Power */
        }
    }

    static const uint8_t key_irqs[8] = {0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15};
    for (int b = 0; b < 8; b++) {
        uint8_t bit = (uint8_t)(1u << b);
        if (mask & bit) {
            if (PMR_KEY_PAD & bit) {
                PMR_KEY_PAD &= (uint8_t)~bit;
                MinxCPU_OnIRQAct(key_irqs[b]);
            }
        } else {
            PMR_KEY_PAD |= bit;
        }
    }
    if (shock && !PokeMini_ShockKey)
        MinxCPU_OnIRQAct(0x10);
    PokeMini_ShockKey = shock;
    prev_keys_mask = mask;
}

static void pm_put_s(char **p, const char *end, const char *s)
{
    while (*s && *p < end) *(*p)++ = *s++;
    **p = 0;
}
static void pm_put_u(char **p, const char *end, u32 v)
{
    char d[12]; int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < end) *(*p)++ = d[--n];
    **p = 0;
}

void pokemini_reset(void)
{
    pm_fill(PM_RAM, 0xFF, 8192);
    pm_copy(PM_IO, PM_IO_INIT, 256);

    pm_zero(&MinxTimers, sizeof(MinxTimers));
    MinxTimers.Tmr1PreA = MinxTimers.Tmr1PreB = 0xFFFFFFFFu;
    MinxTimers.Tmr2PreA = MinxTimers.Tmr2PreB = 0xFFFFFFFFu;
    MinxTimers.Tmr3PreA = MinxTimers.Tmr3PreB = 0xFFFFFFFFu;

    MinxIRQ_MasterIRQ = 1;
    PMR_IRQ_ACT1 = PMR_IRQ_ACT2 = PMR_IRQ_ACT3 = PMR_IRQ_ACT4 = 0;

    pm_zero(&MinxIO, sizeof(MinxIO));
    PokeMini_Rumbling = 0;
    PokeMini_ShockKey = 0;
    prev_keys_mask = 0;
    PMR_KEY_PAD = 0xFFu;
    PMR_SYS_BATT &= 0x1Fu;

    if (EEPROM[0x1FFF] == 0xFFu && EEPROM[0x1FF9] == 0xFFu) {
        uint8_t yr = 26, mo = 11, dy = 22, hr = 12, mn = 0, sc = 0;
        PMR_SYS_CTRL3 |= 0x02u;
        EEPROM[0x1FF6] = 0; EEPROM[0x1FF7] = 0; EEPROM[0x1FF8] = 0;
        EEPROM[0x1FF9] = yr; EEPROM[0x1FFA] = mo; EEPROM[0x1FFB] = dy;
        EEPROM[0x1FFC] = hr; EEPROM[0x1FFD] = mn; EEPROM[0x1FFE] = sc;
        EEPROM[0x1FFF] = (uint8_t)(yr + mo + dy + hr + mn + sc);
    }

    pm_zero(&MinxPRC, sizeof(MinxPRC));
    StallCPU = 0;
    MinxPRC.PRCRateMatch = 0x10;

    pm_zero(WS->lcd_data, sizeof(WS->lcd_data));
    pm_zero(WS->lcd_pix_d, sizeof(WS->lcd_pix_d));
    pm_zero(WS->lcd_pix_a, sizeof(WS->lcd_pix_a));
    pm_zero(WS->lcd_pix_s, sizeof(WS->lcd_pix_s));
    pm_zero(&MinxLCD, sizeof(MinxLCD));
    MinxLCD.LastRead = 0x40;
    MinxLCD_SetContrast(0x1F);

    pm_aud_ccnt = 0;
    pm_aud_vol = 0;
    pm_pwm_mul = 0;
    pm_zero(pm_hp, sizeof(pm_hp));
    pm_zero(pm_lp, sizeof(pm_lp));
    pm_snd_rd = pm_snd_wr = 0;

    pm_zero(&MinxCPU, sizeof(MinxCPU));
    MinxCPU.Status = MINX_STATUS_NORMAL;
    MinxCPU.PC.W.L = ReadMem16(0);
    MinxCPU.E = 0x1F;
    MinxCPU.F = 0xC0;
    Set_U(0);
    MinxCPU_OnIRQHandle(MinxCPU.F, MinxCPU.Shift_U);
}

const char *pokemini_load(const u8 *ext_bios, u8 *image, u32 size)
{
    if (!image || size <= 0x2100u)
        return "Pokemon Mini ROM is too small (must exceed 0x2100 bytes)";
    if (size > PM_MAX_ROM)
        return "Pokemon Mini ROM exceeds 2 MB";

    pm_zero(WS, sizeof(*WS) - PM_MAX_ROM);
    pm_fill(EEPROM, 0xFF, 8192);
    PokeMini_EEPROMWritten = 0;

    if (ext_bios) {
        pm_copy(PM_BIOS, ext_bios, 4096);
        using_freebios = 0;
    } else {
        pm_copy(PM_BIOS, FreeBIOS, 4096);
        using_freebios = 1;
    }

    u32 p2 = 0x4000u;
    while (p2 < size && p2 < PM_MAX_ROM)
        p2 <<= 1;
    PM_ROM_Size = p2;
    PM_ROM_Mask = p2 - 1u;
    pm_fill(PM_ROM, 0xFF, p2);
    pm_copy(PM_ROM, image, size);

    build_lcd_palette();
    pm_snd_hz = 0;
    pm_snd_inc = 0;
    pokemini_reset();

    char title[16];
    int tn = 0;
    for (int i = 0; i < 12; i++) {
        u8 c = PM_ROM[0x21ACu + i];
        if (c >= 0x20u && c <= 0x7Eu)
            title[tn++] = (char)c;
    }
    while (tn > 0 && title[tn - 1] == ' ') tn--;
    title[tn] = 0;

    char *p = pm_info_str, *end = pm_info_str + sizeof(pm_info_str) - 1;
    pm_put_s(&p, end, "Pokemon Mini (");
    pm_put_s(&p, end, using_freebios ? "FreeBIOS" : "bios.min");
    if (tn > 0) {
        pm_put_s(&p, end, ", \"");
        pm_put_s(&p, end, title);
        pm_put_s(&p, end, "\"");
    }
    pm_put_s(&p, end, "), ");
    pm_put_u(&p, end, size >> 10);
    pm_put_s(&p, end, " KB");
    return 0;
}

void pokemini_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture)
{
    pm_set_keys(pad, hid, hid_n);

    PokeMini_FrameDone = 0;
    int guard = 0;
    while (!PokeMini_FrameDone && guard < 16384) {
        PokeHWCycles = 0;
        while (PokeHWCycles < 16) {
            if (StallCPU) PokeHWCycles += 16;
            else PokeHWCycles += MinxCPU_Exec();
        }
        MinxTimers_Sync();
        MinxPRC_Sync();
        if (pm_snd_hz)
            MinxAudio_Sync();
        guard++;
    }

    if (picture) {
        const u16 *pal = WS->lcd_pal;
        const u8 *pix = WS->lcd_pix_a;
        for (int i = 0; i < PM_W * PM_H; i++)
            picture[i] = pal[pix[i]];
    }
}

const char *pokemini_info(void)
{
    return pm_info_str;
}

u8 *pokemini_save_ram(u32 *size, int *battery)
{
    *size = 8192u;
    *battery = 1;
    return EEPROM;
}

int pokemini_save_changed(void)
{
    int w = PokeMini_EEPROMWritten;
    PokeMini_EEPROMWritten = 0;
    return w;
}

int pokemini_jammed(void)
{
    return 0;
}

void pokemini_audio_rate(u32 hz)
{
    if (hz >= 8000u && hz <= 65535u) {
        pm_snd_hz = hz;
        pm_snd_inc = (hz * 65536u) / 15625u;
    } else if (hz > 65535u && hz <= 192000u) {
        pm_snd_hz = hz;
        pm_snd_inc = ((hz >> 2) * 65536u) / 3906u;
    } else {
        pm_snd_hz = 0;
        pm_snd_inc = 0;
    }
    pm_aud_ccnt = 0;
    pm_snd_rd = pm_snd_wr = 0;
}

int pokemini_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && pm_snd_rd != pm_snd_wr)
        out[n++] = WS->snd_ring[pm_snd_rd++ & PM_RING_MASK];
    return n;
}

