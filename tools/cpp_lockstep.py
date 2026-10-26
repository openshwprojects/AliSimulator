"""
Lockstep check of the C++ core against Unicorn: a dump (or a program) on a
minimal board -- RAM, the flash windows, a device window that reads back what
was stored (UART LSR ready, the chip ID) -- runs on both, a code hook records
the PC and the registers before every instruction, and the first difference
is reported with the instructions before it.

  python tools/cpp_lockstep.py ali_sdk.bin 60000
  python tools/cpp_lockstep.py dump_maciej.bin 2000000 --skip 0
"""
import argparse
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.mips_const import UC_CPU_MIPS32_24KF, UC_MIPS_REG_PC
import ctypes

import cpp_core
from simulator import resolve_dump

GPRS = list(range(2, 34)) + [129, 130]      # r0..r31, HI, LO
NAMES = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
         "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra", "hi", "lo"]


def kuseg_tlb(mu):
    """Unicorn: the wired TLB entry that maps kuseg 1:1 (simulator._setup_kuseg_tlb)."""
    from unicorn.mips_const import UC_MIPS_REG_CP0_STATUS
    page = 0x0EFFF000

    def li(v):
        return [0x3C080000 | (v >> 16), 0x35080000 | (v & 0xFFFF)]

    def mtc0(rd):
        return 0x40880000 | rd << 11

    def entry_lo(pa):
        return ((pa >> 12) << 6) | (2 << 3) | 0x7

    code = (li(0x1FFFE000) + [mtc0(5)] + li(0) + [mtc0(10)] + li(entry_lo(0)) + [mtc0(2)] +
            li(entry_lo(0x10000000)) + [mtc0(3)] + li(0) + [mtc0(0)] + li(1) + [mtc0(6)] + [0x42000002, 0])
    mu.mem_map(page, 0x1000)
    mu.mem_write(page, struct.pack(f"<{len(code)}I", *code))
    mu.reg_write(UC_MIPS_REG_CP0_STATUS, 0x10400004)
    mu.emu_start(0x80000000 | page, (0x80000000 | page) + 4 * len(code), count=len(code))
    mu.mem_unmap(page, 0x1000)
    for r in range(2, 34):
        mu.reg_write(r, 0)


class Board:
    """RAM, flash and a plain device window on one engine."""

    def __init__(self, uc, image):
        self.uc = uc
        self.ram = ctypes.create_string_buffer(128 << 20)
        self.rom = ctypes.create_string_buffer(4 << 20)
        ctypes.memmove(self.rom, image[:4 << 20] + b"\xFF" * max(0, (4 << 20) - len(image)), 4 << 20)
        self.mmio = bytearray(16 << 20)
        self.mmio[0x18305] = 0x20
        self.mmio[2:4] = b"\x11\x38"
        self.uart = bytearray()
        uc.mem_map_ptr(0, 128 << 20, 7, ctypes.addressof(self.ram))
        for win in (0x0F000000, 0x1F000000):
            for slot in range(0, 0x01000000, 0x400000):
                uc.mem_map_ptr(win + slot, 4 << 20, 5, ctypes.addressof(self.rom))
        uc.mmio_map(0x18000000, 16 << 20, self._rd, None, self._wr, None)
        if hasattr(uc, "set"):
            uc.set(cpp_core.F_STATUS, 0x10400000)
            # raw Unicorn: Count reads 0, no timer, EBase's CPU number 0x3FF
            cpp_core.lib().ali_set_count_ratio(uc.handle, 0, 1)
            uc.set(cpp_core.F_TIMER_ENABLED, 0)
            uc.set(cpp_core.F_EBASE, 0x800003FF)
        else:
            kuseg_tlb(uc)                      # (the simulator's wired TLB entry: kuseg 1:1)
            uc.reg_write(139, 0x10400000)      # (Unicorn: Status as the simulator sets it)

    def _rd(self, uc, offset, size, user):
        if offset == 0x18305:
            return 0x20
        return int.from_bytes(self.mmio[offset:offset + size], "little")

    def _wr(self, uc, offset, size, value, user):
        if offset == 0x18300:
            self.uart.append(value & 0xFF)
        self.mmio[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def trace(uc, start, count, skip, every):
    """[(pc, regs)] before each instruction after the first `skip` ones."""
    out = []
    n = [0]

    def hook(uc_, address, size, user):
        n[0] += 1
        if n[0] > skip and (n[0] - skip) % every == 0:
            out.append((address, size, tuple(uc_.reg_read(r) for r in GPRS)))

    uc.hook_add(UC_HOOK_CODE, hook)
    err = None
    try:
        uc.emu_start(start, 0xFFFFFFFF, count=count)
    except UcError as e:
        err = e
    return out, err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("count", type=int)
    ap.add_argument("--skip", type=int, default=0, help="instructions not recorded first")
    ap.add_argument("--every", type=int, default=1, help="record every Nth instruction")
    args = ap.parse_args()
    image = open(resolve_dump(args.dump), "rb").read()

    u = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    u.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
    bu = Board(u, image)
    c = cpp_core.CppUc()
    bc = Board(c, image)
    tu, eu = trace(u, 0xAFC00000, args.count, args.skip, args.every)
    tc, ec = trace(c, 0xAFC00000, args.count, args.skip, args.every)
    print(f"unicorn: {len(tu)} records, error {eu}; uart {bytes(bu.uart)[:200]!r}")
    print(f"cpp:     {len(tc)} records, error {ec}; uart {bytes(bc.uart)[:200]!r}")
    for i, (a, b) in enumerate(zip(tu, tc)):
        if a != b:
            print(f"first difference at record {i} (instruction {args.skip + (i + 1) * args.every}):")
            for j in range(max(0, i - 8), i):
                print(f"   ok  pc={tu[j][0]:08X} size {tu[j][1]}")
            print(f"  unicorn pc={a[0]:08X} size {a[1]}   cpp pc={b[0]:08X} size {b[1]}")
            for k, (x, y) in enumerate(zip(a[2], b[2])):
                if x != y:
                    print(f"    {NAMES[k]}: unicorn {x:08X} cpp {y:08X}")
            return 1
    if len(tu) != len(tc):
        print(f"same for {min(len(tu), len(tc))} records, lengths differ")
        return 1
    print(f"identical for {len(tu)} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
