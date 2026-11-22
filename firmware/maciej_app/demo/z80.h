/* z80.c: a Zilog Z80 -- every instruction, the documented ones and the
   others (the halves of IX and IY, SLL, the DDCB / FDCB forms that also
   write a register, the ED mirrors), the flags as the chip sets them (the
   two unnamed ones too, from MEMPTR on BIT n,(HL), and SCF / CCF's from the
   flags the previous instruction left), the R register, interrupt modes 0
   (the bus's byte taken as an RST), 1 and 2, NMI, HALT, the one instruction
   after EI with no interrupt.  Time is counted in T-states, memory access
   by memory access, so a machine whose chips slow the CPU down (the ZX
   Spectrum's) can say by how much at each access.

   Shared by the Sega Master System (sms.c), the ZX Spectrum (zx.c) and the
   Mega Drive (md.c, its sound CPU).  Nothing in it knows any of them: the
   machine fills in the memory map (1 KB pages; a page without memory read
   through read(), as the Mega Drive's sound chip and its window on the
   68000's bus are), the I/O port handlers and, when it has one, its
   contention table. */
#ifndef DEMO_Z80_H
#define DEMO_Z80_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;

/* a register pair, its two halves addressable (both the box's MIPS and a PC are little-endian) */
union z80_pair {
    u16 w;
    struct {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        u8 h, l;
#else
        u8 l, h;
#endif
    } b;
};

struct z80 {
    union z80_pair af, bc, de, hl, ix, iy, sp, pc, wz;  /* (wz: MEMPTR, the chip's hidden address register) */
    u16 af2, bc2, de2, hl2;             /* the other set (EX AF,AF' and EXX) */
    u8 i, r, r7;                        /* R: its low 7 bits count, bit 7 is r7's (as LD R,A left it) */
    u8 iff1, iff2, im, halted;
    u8 ei_block;                        /* 1 just after EI (or a prefix): no maskable interrupt before the next */
    u8 q, q_was;                        /* the flags the last instruction set (0: it set none); SCF / CCF use it */
    u8 irq;                             /* the machine holds the INT line low (level: it lowers and raises it) */
    u8 nmi;                             /* an NMI's edge came: taken before the next instruction */
    u8 bus;                             /* the byte on the data bus when an interrupt is acknowledged (0xFF) */
    s32 cycles;                         /* T-states: z80_run goes on until it reaches its target */
    s32 trap;                           /* z80_run stops when the PC comes to this address (-1: never) */
    u8 *rd[64];                         /* the memory map, 1 KB pages: where reads of each come from (0: from
                                           read() instead) */
    u8 *wr[64];                         /* where writes go (0: to write() instead) */
    u8 *op[64];                         /* M1 opcode fetch pages when distinct from rd[] (Kabuki Z80; 0: rd[]) */
    u8 (*read)(struct z80 *c, u16 address);
    void (*write)(struct z80 *c, u16 address, u8 value);
    u8 (*in)(struct z80 *c, u16 port);
    void (*out)(struct z80 *c, u16 port, u8 value);
    void (*irq_ack)(struct z80 *c);     /* optional M1|IORQ interrupt acknowledge hook (Amstrad CPC Gate Array) */
    /* contended memory (the ZX Spectrum's): an access to an address from cont_lo to cont_lo + cont_n - 1 at
       T-state t is first held up by cont[t] T-states; I/O ports are held up as the Spectrum's ULA holds them.
       cont_n 0: none (cont is then never read) */
    u16 cont_lo, cont_n;
    const u8 *cont;
    void *user;                         /* the machine's own */
};

void z80_init(struct z80 *c);           /* the flag tables (once), the registers as at power-on */
void z80_reset(struct z80 *c);          /* the RESET line: PC 0, interrupts off, mode 0 */
int z80_run(struct z80 *c, s32 until);  /* instructions until c->cycles >= until: 0; 1: stopped at c->trap
                                           (before running the instruction there: the caller moves the PC on) */

#define Z80_FC 0x01
#define Z80_FN 0x02
#define Z80_FP 0x04
#define Z80_FX 0x08
#define Z80_FH 0x10
#define Z80_FY 0x20
#define Z80_FZ 0x40
#define Z80_FS 0x80

#endif
