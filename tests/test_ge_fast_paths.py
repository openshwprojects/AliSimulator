"""
Test (fast): the GE_M36F model's fast paths (ge_m36f.py: fast_paths) draw the
same pixels as its general path, which decodes every pixel to float ARGB and
encodes it again.  Random commands run on two copies of a random RAM image,
one model with the fast paths and one without, and the images must stay equal
byte for byte:

  copies   - PTN bitmap bypass (ROP 1) between surfaces of one format: the
             packed RGB formats (with and without alpha), CLUT4 / CLUT8 / A8 /
             ACLUT44 (index domain), with random RGB order, byte endian, RGB
             expansion, alpha range / polarity bits, clip rectangles, odd
             sizes and positions (the fast path takes only those where the
             general path gives back the raw values -- in formats with unused
             bits, those come out 0)
  source copies - SRC bypass (ROP 0) the same way, with the SRC position
             0x0FFF0FFF (= the DST's) and a SRC format of pitch 0 (= the DST's)
  fills    - draw / back colour fills (primitive 4 / 3) into each format
  subbyte  - 4-, 2- and 1-bit surfaces, written through the vectorised
             sub-byte path (ufunc.at), also with a clip mask
  edges    - regions that leave the RAM or whose rows overlap (pitch below
             the width) take the row-by-row fallback
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import numpy as np

import ge_m36f

RAM = 1 << 20
fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def regs(**kw):
    r = [0] * 64
    for k, v in kw.items():
        r[int(k[1:], 16) >> 2] = v & 0xFFFFFFFF
    return r


def pf(fmt, pitch, flags=0):
    return (flags & ~0x1F000 & ~0xFFF) | (fmt << 12) | pitch


def run_both(commands, seed):
    """Run the commands on two copies of one random RAM image; (equal, differing bytes, primitives)."""
    rng = np.random.default_rng(seed)
    base = rng.integers(0, 256, RAM, dtype=np.uint8)
    out = []
    for fast in (True, False):
        ram = base.copy()
        ge = ge_m36f.GeM36F(ram)
        ge.fast_paths = fast
        for r in commands:
            ge.execute(list(r))
        out.append((ram, ge))
    (a, ga), (b, gb) = out
    diff = int(np.count_nonzero(a != b))
    return diff == 0 and not ga.unsupported and not gb.unsupported, diff, ga.primitives


def copy_cmd(rng, fmt, w, h, flags_src, flags_dst, clip=False):
    bpp = ge_m36f.BPP[fmt]
    pitch = int(rng.integers(w, w + 40))
    src, dst = 0x10000, 0x60000
    m = (1 << 3) | (1 << 21) | ((1 << 28) if clip else 0)        # PTN bitmap, ROP 1 (PTN bypass)
    kw = dict(a30=m, a34=dst, a38=pf(fmt, pitch, flags_dst), a3c=int(rng.integers(0, 20)) | int(rng.integers(0, 20)) << 16,
              a40=w | h << 16, a50=src, a54=pf(fmt, pitch, flags_src),
              a58=int(rng.integers(0, 20)) | int(rng.integers(0, 20)) << 16, a5c=w | h << 16)
    if clip:
        kw.update(a7c=int(rng.integers(0, 10)) | int(rng.integers(0, 10)) << 16,
                  a80=int(rng.integers(w // 2, w + 10)) | int(rng.integers(h // 2, h + 10)) << 16)
    return regs(**kw)


def src_copy_cmd(rng, fmt, w, h, flags_src, flags_dst, clip=False):
    """SRC bypass (ROP 0, SRC mode 1); now and then the SRC position 0x0FFF0FFF (= the DST's) or a SRC
    pixel format with pitch 0 (= the DST's)."""
    pitch = int(rng.integers(w, w + 40))
    m = 1 | ((1 << 28) if clip else 0)
    dxy = int(rng.integers(0, 20)) | int(rng.integers(0, 20)) << 16
    sxy = 0x0FFF0FFF if rng.random() < 0.2 else int(rng.integers(0, 20)) | int(rng.integers(0, 20)) << 16
    spf = 0 if rng.random() < 0.2 else pf(fmt, pitch, flags_src)
    kw = dict(a30=m, a34=0x60000, a38=pf(fmt, pitch, flags_dst), a3c=dxy, a40=w | h << 16, a44=0x10000, a48=spf,
              a4c=sxy)
    if clip:
        kw.update(a7c=int(rng.integers(0, 10)) | int(rng.integers(0, 10)) << 16,
                  a80=int(rng.integers(w // 2, w + 10)) | int(rng.integers(h // 2, h + 10)) << 16)
    return regs(**kw)


def fill_cmd(rng, fmt, w, h, prim, col_fmt, flags):
    pitch = int(rng.integers(w, w + 40))
    m = (prim << 8) | (1 << 21)                                   # fill, ROP 1
    return regs(a30=m, a34=0x80000, a38=pf(fmt, pitch, flags), a3c=int(rng.integers(0, 30)) | int(rng.integers(0, 30)) << 16,
                a40=w | h << 16, a90=int(rng.integers(0, 1 << 32)), a98=int(rng.integers(0, 1 << 32)), a9c=col_fmt)


rng = np.random.default_rng(1)
FLAG_BITS = (0x00020000, 0x00040000, 0x00080000, 0x00800000, 0x01000000, 0x02000000)   # order, expansion, endian, alpha


def flags():
    return sum(b for b in FLAG_BITS if rng.random() < 0.3)


print("--- copies")
for fmt in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x0C, 0x1D, 0x08, 0x09):
    cmds = []
    for _ in range(30):
        w, h = int(rng.integers(1, 60)), int(rng.integers(1, 40))
        same = rng.random() < 0.5
        fs = flags()
        cmds.append(copy_cmd(rng, fmt, w, h, fs, fs if same else flags(), clip=rng.random() < 0.3))
    ok, diff, n = run_both(cmds, seed=fmt)
    check(ok, f"format 0x{fmt:02X}: {n} copies, {diff} bytes differ")

print("--- source copies")
for fmt in (0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0C, 0x1D):
    cmds = []
    for _ in range(30):
        fs = flags()
        cmds.append(src_copy_cmd(rng, fmt, int(rng.integers(1, 60)), int(rng.integers(1, 40)), fs,
                                 fs if rng.random() < 0.5 else flags(), clip=rng.random() < 0.3))
    ok, diff, n = run_both(cmds, seed=50 + fmt)
    check(ok, f"format 0x{fmt:02X}: {n} SRC copies, {diff} bytes differ")

print("--- fills")
for fmt in (0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x13, 0x10):
    cmds = [fill_cmd(rng, fmt, int(rng.integers(1, 80)), int(rng.integers(1, 50)), int(rng.choice([3, 4])),
                     int(rng.choice([0x01, 0x05, 0x06])), flags()) for _ in range(30)]
    ok, diff, n = run_both(cmds, seed=100 + fmt)
    check(ok, f"format 0x{fmt:02X}: {n} fills, {diff} bytes differ")

print("--- subbyte")
for fmt in (0x0A, 0x08, 0x09):
    cmds = [copy_cmd(rng, fmt, int(rng.integers(1, 70)), int(rng.integers(1, 30)), 0x00400000 * int(rng.integers(0, 2)),
                     0x00400000 * int(rng.integers(0, 2)), clip=True) for _ in range(10)]
    ok, diff, n = run_both(cmds, seed=200 + fmt)
    check(ok, f"{ge_m36f.BPP[fmt]}-bit surfaces: {n} copies with clip masks, {diff} bytes differ")

print("--- edges")
r1 = copy_cmd(rng, 0x01, 40, 20, 0, 0)
r1[0x34 >> 2] = RAM - 40 * 4 * 10                                 # the DST runs past the end of the RAM
r2 = copy_cmd(rng, 0x05, 40, 20, 0, 0)
r2[0x38 >> 2] = pf(0x05, 10)                                      # pitch below the width: rows overlap
r2[0x54 >> 2] = pf(0x05, 10)
ok, diff, n = run_both([r1, r2], seed=300)
check(ok, f"a region past the end of the RAM, overlapping rows: {diff} bytes differ")

print()
if fails:
    print(f"\033[91m{len(fails)} GE fast-path check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll GE fast-path checks passed\033[0m")
