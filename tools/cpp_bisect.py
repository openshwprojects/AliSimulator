"""
Fast check of the C++ core against Unicorn over long runs: both run a dump N
instructions from reset on the lockstep board (tools/cpp_lockstep.py) without
hooks, then their registers, RAM and device registers are compared; on a
difference the run is bisected to the first instruction count where they
differ, and that instruction is shown.

  python tools/cpp_bisect.py dump.bin 20000000
"""
import argparse
import ctypes
import hashlib
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN
from unicorn.mips_const import UC_CPU_MIPS32_24KF

import cpp_core
from cpp_lockstep import Board, GPRS, NAMES
from simulator import resolve_dump


def state(uc, board, n, image, unicorn):
    """Run n instructions from reset; (registers, RAM digest, device digest, error)."""
    err = None
    try:
        uc.emu_start(0xAFC00000, 0xFFFFFFFF, count=n)
    except UcError as e:
        err = str(e)
    regs = tuple(uc.reg_read(r) for r in GPRS)
    ram = hashlib.sha1(board.ram.raw).hexdigest()
    dev = hashlib.sha1(bytes(board.mmio)).hexdigest()
    return regs, ram, dev, err


def run(engine, image, n):
    if engine == "unicorn":
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
    else:
        uc = cpp_core.CppUc()
    board = Board(uc, image)
    s = state(uc, board, n, image, engine == "unicorn")
    return s, uc, board


def same(a, b):
    return a[0] == b[0] and a[1] == b[1] and a[2] == b[2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("count", type=int)
    args = ap.parse_args()
    image = open(resolve_dump(args.dump), "rb").read()
    (su, _, _), (sc, _, _) = run("unicorn", image, args.count), run("cpp", image, args.count)
    print(f"unicorn error: {su[3]}  cpp error: {sc[3]}")
    if same(su, sc):
        print(f"identical after {args.count} instructions")
        return 0
    lo, hi = 0, args.count            # lo: same, hi: different
    while hi - lo > 1:
        mid = (lo + hi) // 2
        a, b = run("unicorn", image, mid)[0], run("cpp", image, mid)[0]
        if same(a, b):
            lo = mid
        else:
            hi = mid
        print(f"  {lo}..{hi}", flush=True)
    (a, uu, bu), (b, uc, bc) = run("unicorn", image, hi), run("cpp", image, hi)
    print(f"first difference after instruction {hi}")
    for k, (x, y) in enumerate(zip(a[0], b[0])):
        if x != y:
            print(f"    {NAMES[k]}: unicorn {x:08X} cpp {y:08X}")
    if a[1] != b[1]:
        diff = [i for i in range(0, len(bu.ram.raw), 4) if bu.ram.raw[i:i + 4] != bc.ram.raw[i:i + 4]][:8]
        print("    RAM differs at", [hex(d) for d in diff])
    if a[2] != b[2]:
        diff = [i for i in range(len(bu.mmio)) if bu.mmio[i] != bc.mmio[i]][:8]
        print("    device registers differ at", [hex(d) for d in diff])
    # the instruction: run hi-1 on the C++ core and show its PC / instruction
    s, uc1, b1 = run("cpp", image, hi - 1)
    pc, m16 = uc1.get(cpp_core.F_PC_MODE) & ~1, uc1.get(cpp_core.F_M16)
    raw = bytes(uc1.mem_read(pc & 0x1FFFFFFF if pc >= 0x80000000 else pc, 4))
    print(f"    instruction {hi} at 0x{pc:08X} ({'MIPS16' if m16 else 'MIPS32'}): {raw.hex()}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
