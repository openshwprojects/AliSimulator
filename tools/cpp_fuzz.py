"""
Random-instruction check of the C++ core against Unicorn: one instruction
(MIPS32, MIPS16e plain / EXTENDed, FPU) from random registers -- some of them
pointing into a mapped data page, so loads and stores land -- runs on both;
the registers, HI / LO, the FPU registers, the data page and the error must be
the same.  A branch runs with its delay slot (a NOP).

  python tools/cpp_fuzz.py 20000          MIPS32 + MIPS16
  python tools/cpp_fuzz.py 20000 --seed 5 --only m16
"""
import argparse
import os
import random
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN
from unicorn.mips_const import UC_CPU_MIPS32_24KF, UC_MIPS_REG_PC, UC_MIPS_REG_CP0_STATUS

import cpp_core

CODE = 0x00100000           # the instruction (kuseg = physical: no translation question)
DATA = 0x00200000           # the data page base registers point into
GPRS = list(range(2, 34)) + [129, 130]


def insn_size(code, m16):
    if not m16:
        return 4
    return 4 if (code[1] >> 3) in (0x1E, 0x03) else 2


def make(engine):
    if engine == "unicorn":
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
    else:
        uc = cpp_core.CppUc()
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x2000)
    return uc


def setup(uc, regs, fregs, data, status, fcsr, engine):
    for r, v in zip(GPRS, regs):
        uc.reg_write(r, v)
    if engine == "unicorn":
        uc.reg_write(UC_MIPS_REG_CP0_STATUS, status | 4)     # (ERL: kuseg 1:1 in Unicorn)
    else:
        uc.set(cpp_core.F_STATUS, status | 4)
        cpp_core.lib().ali_set_count_ratio(uc.handle, 0, 1)
        uc.set(cpp_core.F_TIMER_ENABLED, 0)
    for i, v in enumerate(fregs or ()):
        if engine != "unicorn":     # (Unicorn: set through code, see run)
            uc.reg_write(cpp_core.REG_F0 + i, v)
    uc.mem_write(DATA, data)


def run(engine, code, regs, fregs, data, status, fcsr, count, m16):
    uc = make(engine)
    uc.mem_write(CODE, code)
    setup(uc, regs, fregs, data, status, fcsr, engine)
    if engine == "unicorn" and fregs is not None:
        # load the FPU registers with MTC1 / MTHC1 and FCSR with CTC1, from a preamble
        pre = []
        for i, v in enumerate(fregs):
            pre += [0x3C080000 | (v & 0xFFFFFFFF) >> 16, 0x35080000 | (v & 0xFFFF),            # t0 = low
                    0x44880000 | i << 11,                                                    # mtc1 t0, $fi
                    0x3C080000 | (v >> 48), 0x35080000 | ((v >> 32) & 0xFFFF),               # t0 = high
                    0x44E80000 | i << 11]                                                    # mthc1 t0, $fi
        pre += [0x3C080000 | fcsr >> 16, 0x35080000 | (fcsr & 0xFFFF), 0x44C8F800]          # ctc1 t0, $31
        pre_addr = CODE + 0x800
        uc.mem_write(pre_addr, struct.pack(f"<{len(pre)}I", *pre))
        t0 = uc.reg_read(10)
        uc.reg_write(UC_MIPS_REG_CP0_STATUS, 0x34400004)        # (FR = 1: the 64-bit registers as they are)
        uc.emu_start(pre_addr, pre_addr + 4 * len(pre))
        uc.reg_write(UC_MIPS_REG_CP0_STATUS, status | 4)
        uc.reg_write(10, t0)
    elif engine == "cpp" and fregs is not None:
        uc.reg_write(141, fcsr)
    err = None
    invalid = []
    if engine == "unicorn":
        from unicorn.unicorn_const import UC_HOOK_MEM_INVALID
        uc.hook_add(UC_HOOK_MEM_INVALID, lambda *a: (a[1] != 21 and invalid.append(a[1:4])) and False)
    try:
        if count == -1:
            uc.emu_start(CODE | (1 if m16 else 0), 0xFFFFFFFF, count=1)
        elif count == 1:    # (a plain instruction: until its end -- Unicorn's count limit garbles errors)
            size = len(code) - 16 - (2 if m16 and False else 0)
            uc.emu_start(CODE | (1 if m16 else 0), CODE + (insn_size(code, m16)))
        else:
            uc.emu_start(CODE | (1 if m16 else 0), 0xFFFFFFFF, count=count)
    except UcError as e:
        err = e.errno
        if engine == "unicorn" and err == 6 and not invalid:
            err = None          # (Unicorn's error when the count runs out: nothing was read)
    out = [uc.reg_read(r) for r in GPRS]
    if fregs is not None:
        if engine == "unicorn":
            # read the FPU registers back with MFC1 / MFHC1 into the data page's second half
            post = []
            for i in range(32):
                post += [0x44080000 | i << 11, 0xAD280000 | (8 * i),          # mfc1 t0, $fi; sw t0, 8i(t1)
                         0x44680000 | i << 11, 0xAD280000 | (8 * i + 4)]      # mfhc1 t0, $fi; sw t0, 8i+4(t1)
            post += [0x44480000 | 31 << 11, 0xAD280100]                       # cfc1 t0, $31; sw t0, 0x100(t1)
            uc.reg_write(11, DATA + 0x1000)
            uc.mem_write(CODE + 0x400, struct.pack(f"<{len(post)}I", *post))
            uc.reg_write(UC_MIPS_REG_CP0_STATUS, 0x34400004)
            uc.emu_start(CODE + 0x400, CODE + 0x400 + 4 * len(post))
            blob = bytes(uc.mem_read(DATA + 0x1000, 0x104))
            fout = list(struct.unpack("<32Q", blob[:256])) + [struct.unpack_from("<I", blob, 256)[0]]
        else:
            fout = [uc.reg_read(cpp_core.REG_F0 + i) for i in range(32)] + [uc.reg_read(141)]
    else:
        fout = None
    mem = bytes(uc.mem_read(DATA, 0x1000))
    return out, fout, mem, err


# ---- instruction generators ----
def r5(rng):
    return rng.randrange(32)


def gen_m32(rng):
    """A random MIPS32 instruction in its canonical encoding (as compilers emit it):
    integer, memory, bit-field, branch, CP0 and FPU groups."""
    kind = rng.random()
    rs, rt, rd, sa = r5(rng), r5(rng), r5(rng), r5(rng)
    imm = rng.randrange(0x10000)
    if kind < 0.30:   # SPECIAL
        funct = rng.choice([0x00, 0x02, 0x03, 0x04, 0x06, 0x07, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19,
                            0x1A, 0x1B, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x30, 0x31,
                            0x32, 0x33, 0x34, 0x36, 0x0F])
        if funct in (0x00, 0x02, 0x03):
            rs = 1 if funct == 0x02 and rng.random() < 0.5 else 0          # (ROTR: rs = 1)
        elif funct in (0x04, 0x06, 0x07, 0x0A, 0x0B, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B):
            sa = 1 if funct == 0x06 and rng.random() < 0.5 else 0          # (ROTRV: sa = 1)
        elif funct in (0x10, 0x12):
            rs = rt = sa = 0
        elif funct in (0x11, 0x13):
            rt = rd = sa = 0
        elif funct in (0x18, 0x19, 0x1A, 0x1B):
            rd = sa = 0
        elif funct == 0x0F:
            rs = rt = rd = 0
        return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct, False
    if kind < 0.45:   # immediate ALU
        op = rng.choice([0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        if op == 0x0F:
            rs = 0
        return (op << 26) | (rs << 21) | (rt << 16) | imm, False
    if kind < 0.60:   # loads / stores off a data pointer (rs = s0..s3)
        op = rng.choice([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x29, 0x2A, 0x2B, 0x2E, 0x30, 0x38])
        base = rng.choice([16, 17, 18, 19])
        off = rng.randrange(-64, 64) & 0xFFFF
        return (op << 26) | (base << 21) | (rt << 16) | off, False
    if kind < 0.70:   # SPECIAL2 / SPECIAL3
        if rng.random() < 0.5:
            funct = rng.choice([0x00, 0x01, 0x02, 0x04, 0x05, 0x20, 0x21])
            if funct in (0x00, 0x01, 0x04, 0x05):
                rd = 0
            if funct in (0x20, 0x21):
                rt = rd                                                 # (CLZ / CLO: rt = rd)
            return (0x1C << 26) | (rs << 21) | (rt << 16) | (rd << 11) | funct, False
        funct = rng.choice([0x00, 0x04, 0x20, 0x20, 0x20])
        if funct == 0x20:
            sa = rng.choice([0x02, 0x10, 0x18])
            rs = 0
        elif funct == 0x00:
            sa = rng.randrange(32)
            rd = rng.randrange(32 - sa)                                 # (EXT: pos + size <= 32)
        else:
            sa = rng.randrange(32)
            rd = rng.randrange(sa, 32)                                  # (INS: msb >= lsb)
        return (0x1F << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct, False
    if kind < 0.80:   # branches / jumps (with a NOP delay slot)
        op = rng.choice([0x01, 0x04, 0x05, 0x06, 0x07, 0x14, 0x15, 0x16, 0x17, 0x00, 0x02, 0x03, 0x1D])
        off = rng.randrange(-16, 16) & 0xFFFF
        if op == 0x01:
            rt = rng.choice([0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13])
            return (op << 26) | (rs << 21) | (rt << 16) | off, True
        if op == 0x00:
            return (max(rs, 1) << 21) | (rd << 11) | rng.choice([0x08, 0x09]), "jr"
        if op in (0x02, 0x03, 0x1D):
            return (op << 26) | (((CODE >> 2) + rng.randrange(64)) & 0x03FFFFFF), True
        if op in (0x06, 0x07, 0x16, 0x17):
            rt = 0
        return (op << 26) | (rs << 21) | (rt << 16) | off, True
    if kind < 0.85:   # MFC0 / MTC0 of plain registers, DI / EI
        if rng.random() < 0.3:
            return 0x41606000 | (rt << 16) | rng.choice([0, 0x20]), False
        rdsel = rng.choice([(4, 0), (5, 0), (10, 0), (14, 0), (16, 0), (16, 1), (28, 0), (29, 0), (30, 0), (31, 0),
                            (15, 0), (8, 0)])
        op = rng.choice([0x40000000, 0x40800000])
        return op | (rt << 16) | (rdsel[0] << 11) | rdsel[1], False
    # FPU
    return gen_fpu(rng), "fpu"


def gen_fpu(rng):
    fs, ft, fd = r5(rng), r5(rng), r5(rng)
    k = rng.random()
    if k < 0.15:
        sub = rng.choice([0x00, 0x03, 0x04, 0x07])     # MFC1 / MFHC1 / MTC1 / MTHC1
        return (0x11 << 26) | (sub << 21) | (r5(rng) << 16) | (fs << 11)
    if k < 0.25:   # LWC1 / SWC1 / LDC1 / SDC1
        op = rng.choice([0x31, 0x39, 0x35, 0x3D])
        base = rng.choice([16, 17])
        off = (rng.randrange(-8, 8) * 8) & 0xFFFF
        return (op << 26) | (base << 21) | (ft << 16) | off
    if k < 0.35:   # W / L conversions
        fmt = rng.choice([0x14, 0x15])
        funct = rng.choice([0x20, 0x21])
        if fmt == 0x15:
            fs &= ~1
            fd &= ~1
        if funct == 0x21:
            fd &= ~1
        return (0x11 << 26) | (fmt << 21) | (fs << 11) | (fd << 6) | funct
    fmt = rng.choice([0x10, 0x11])
    funct = rng.choice([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0C, 0x0D, 0x0E, 0x0F, 0x20, 0x21, 0x24,
                        0x12, 0x13] + list(range(0x30, 0x40)))
    if fmt == 0x11:
        fs &= ~1
        ft &= ~1
        if funct not in (0x20, 0x24, 0x0C, 0x0D, 0x0E, 0x0F) and funct < 0x30:
            fd &= ~1
    else:
        if funct == 0x21:
            fd &= ~1
    if funct in (0x12, 0x13):
        ft = r5(rng)
    if funct >= 0x30:
        fd = rng.randrange(8) << 2
    return (0x11 << 26) | (fmt << 21) | (ft << 16) | (fs << 11) | (fd << 6) | funct


def gen_m16(rng):
    """A random MIPS16e instruction: (bytes, has a delay slot)."""
    k = rng.random()
    ext = rng.random() < 0.35
    while True:
        op = rng.choice([0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x10, 0x11,
                         0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x03])
        rx, ry = rng.randrange(8), rng.randrange(8)
        low = rng.randrange(0x100)
        if op in (0x02, 0x04, 0x05) or (op == 0x0C and ((low >> 0) & 0) == 0 and False):
            pass
        if op == 0x03:   # JAL / JALX
            hw = (0x03 << 11) | (rng.randrange(2) << 10) | ((CODE >> 18) & 0x1F) << 5 | ((CODE >> 23) & 0x1F)
            hw2 = ((CODE + 2 * rng.randrange(32)) >> 2) & 0xFFFF
            return struct.pack("<HH", hw, hw2), True
        if op == 0x1D:
            funct = rng.choice([0x00, 0x02, 0x03, 0x04, 0x06, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                0x11, 0x12, 0x18, 0x19, 0x1A, 0x1B])
            if funct == 0x00:
                sel = rng.choice([0, 1, 2, 4, 5, 6])
                hw = (op << 11) | (rx << 8) | (sel << 5)
                return struct.pack("<H", hw), True if sel in (0, 1, 2) else "jump"
            if funct == 0x11:
                ry = rng.choice([0, 1, 4, 5])
            hw = (op << 11) | (rx << 8) | (ry << 5) | funct
            return struct.pack("<H", hw), False
        if op == 0x1C:
            hw = (op << 11) | (rx << 8) | (ry << 5) | (rng.randrange(8) << 2) | rng.choice([1, 3])
            return struct.pack("<H", hw), False
        if op == 0x0C:
            f = rng.choice([0, 1, 2, 3, 4, 5, 7])
            hw = (op << 11) | (f << 8) | low
            if f == 4 and not ext:
                hw &= ~0x80 if rng.random() < 0.5 else 0xFFFF   # SAVE / RESTORE
        elif op == 0x06:
            hw = (op << 11) | (rx << 8) | (ry << 5) | (rng.randrange(8) << 2) | rng.choice([0, 2, 3])
            if ext:
                hw &= ~0x1C
        elif op == 0x08:
            hw = (op << 11) | (rx << 8) | (ry << 5) | rng.randrange(16)
        else:
            hw = (op << 11) | (rx << 8) | low
        if op in (0x10, 0x11, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1B):
            hw = (op << 11) | (rx << 8) | (ry << 5) | rng.randrange(32)
        if ext:
            if op == 0x0C and ((hw >> 8) & 7) == 4:
                e = (0x1E << 11) | (rng.randrange(8) << 8) | (rng.randrange(4) << 4) | rng.choice(
                    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])
            elif op == 0x08:
                e = (0x1E << 11) | rng.randrange(0x800)
            else:
                e = (0x1E << 11) | rng.randrange(0x800)
            if op in (0x10, 0x11, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1B, 0x12, 0x1A, 0x16) or \
                    (op == 0x0C and ((hw >> 8) & 7) == 2):
                # keep memory offsets small (sign-extended 16-bit from ext imm[15:11|10:5] + hw[4:0])
                off = rng.randrange(-64, 64) & 0xFFFF
                e = (0x1E << 11) | (((off >> 5) & 0x3F) << 5) | ((off >> 11) & 0x1F)
                hw = (hw & ~0x1F) | (off & 0x1F)
            return struct.pack("<HH", e, hw), False
        return struct.pack("<H", hw), False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("count", type=int)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", choices=["m32", "m16", "fpu"])
    ap.add_argument("--case", type=int, help="show case N in detail (registers, both results)")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    fails = 0
    for n in range(args.count):
        regs = [0] + [rng.choice([rng.randrange(1 << 32), rng.randrange(64), DATA + rng.randrange(0x100, 0xF00)])
                      for _ in range(31)] + [rng.randrange(1 << 32), rng.randrange(1 << 32)]
        for base in (16, 17, 18, 19, 29):      # s0..s3, sp: data pointers
            regs[base] = DATA + 0x400 + 4 * rng.randrange(0x100) + (rng.random() < 0.1) * rng.randrange(4)
        regs[29] &= ~3                          # (sp: aligned, as SAVE / RESTORE need)
        for r in (2, 3, 4, 5, 6, 7):            # (MIPS16's registers: data pointers too, never kseg2)
            if rng.random() < 0.5:
                regs[r] = DATA + 0x400 + 2 * rng.randrange(0x200)
        data = bytes(rng.randrange(256) for _ in range(0x1000))
        status = 0x10400000
        fregs, fcsr = None, 0
        which = args.only or rng.choice(["m32", "m32", "m16", "fpu"])
        if which == "m16":
            insn, ds = gen_m16(rng)
            code = insn + (struct.pack("<H", 0x6500) if ds else b"") + b"\x00" * 16
            count, m16 = (2 if ds else 1), True
        else:
            w, ds = gen_m32(rng) if which == "m32" else (gen_fpu(rng), "fpu")
            if ds == "jr":                          # (a register jump: to the code page)
                regs[(w >> 21) & 31] = CODE + 4 * rng.randrange(1, 64) + (rng.random() < 0.2)
                ds = True
            if ds == "fpu" or which == "fpu":
                status |= 0x20000000 | (rng.choice([0, 0x04000000]))      # CU1, FR 0 / 1
                fregs = [rng.choice([rng.randrange(1 << 64), struct.unpack("<Q", struct.pack("<d", rng.uniform(-1e6, 1e6)))[0],
                                     struct.unpack("<I", struct.pack("<f", rng.uniform(-1e3, 1e3)))[0] |
                                     (rng.randrange(1 << 32) << 32)]) for _ in range(32)]
                fcsr = rng.choice([0, 0, 1, 2, 3]) | (rng.randrange(2) << 23)
                ds = False
            code = struct.pack("<II", w, 0) + b"\x00" * 16
            count, m16 = (2 if ds else 1), False
        if args.case is not None and n != args.case:
            continue
        if args.case is not None:
            print(f"case {n}: code {code[:8].hex()} m16 {m16} count {count}")
            print("  regs", " ".join(f"{GPRS[i]}={v:08X}" for i, v in enumerate(regs)))
        try:
            a = run("unicorn", code, regs, fregs, data, status, fcsr, count, m16)
        except OSError as e:          # (Unicorn itself crashed on it: not comparable)
            print(f"#{n} {which} {code[:4].hex()}: Unicorn crashed ({e})")
            continue
        b = run("cpp", code, regs, fregs, data, status, fcsr, count, m16)
        if args.case is not None:
            print("  unicorn err", a[3], "cpp err", b[3])
            for i, (x, y) in enumerate(zip(a[0], b[0])):
                if x != regs[i] or y != regs[i]:
                    print(f"    reg {GPRS[i]}: before {regs[i]:08X} unicorn {x:08X} cpp {y:08X}")
        if a != b:
            fails += 1
            print(f"#{n} {which} {code[:4].hex()} status {status:08X}: unicorn err {a[3]}, cpp err {b[3]}")
            for i, (x, y) in enumerate(zip(a[0], b[0])):
                if x != y:
                    print(f"    reg {GPRS[i]}: unicorn {x:08X} cpp {y:08X}")
            if a[1] != b[1] and a[1] and b[1]:
                for i, (x, y) in enumerate(zip(a[1], b[1])):
                    if x != y:
                        print(f"    f{i if i < 32 else 'csr'}: unicorn {x:016X} cpp {y:016X}")
            if a[2] != b[2]:
                d = [i for i in range(0x1000) if a[2][i] != b[2][i]]
                print(f"    data differs at {[hex(DATA + i) for i in d[:8]]}")
            if fails >= 30:
                break
    print(f"{args.count} instructions, {fails} differences")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
