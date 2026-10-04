"""
Unit test (fast): the GE_M36F graphics-engine model (ge_m36f.py) and the GMA
display capture (gma_capture.py) on a small synthetic RAM image, with the
register layouts the dump_maciej firmware uses:

  1. a command list (0x81 base-register header + 0x02 group header) runs a
     draw-colour rectangle fill into an ARGB1555 surface,
  2. an RLE-coded ARGB1555 bitmap (control byte < 0x80 = run, >= 0x80 =
     literals, the stream continuing across rows) is copied with a colour key
     (magenta keyed out, RGB expansion = zero padding),
  3. the anti-aliased text path: big-endian glyph dwords byte-swapped by a
     blit, a 4-bit glyph read with sub-byte endian 1 (left pixel in the high
     nibble) and stretched x2 into an A8 mask, then the font colour
     alpha-blended through that mask,
  4. gma_capture follows layer 0's head pointer to the bitmap and renders it.
"""
import struct
import sys

import numpy as np

import ge_m36f
import gma_capture

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def regs(**kw):
    r = [0] * 64
    for k, v in kw.items():
        r[int(k[1:], 16) >> 2] = v
    return r


def px1555(ram, base, pitch, x, y):
    return int(ram[base + 2 * (y * pitch + x):base + 2 * (y * pitch + x) + 2].view('<u2')[0])


def main():
    print("=== Unit test: GE_M36F model + GMA capture ===")
    ram = np.zeros(0x200000, np.uint8)
    g = ge_m36f.GeM36F(ram)
    SURF, PITCH = 0x100000, 64          # 64x64 ARGB1555 surface

    # 1. command list: base register 1 = SURF, then fill 10x5 at (3, 4) with draw colour 0x83E0 (green)
    mode = (4 << 8) | (1 << 21)         # primitive 4 (draw colour), ROP 1 (PTN bypass)
    words = [0x81 << 24 | 0xC0 << 8 | 1, SURF,
             0x02 << 24 | (1 << 0) | (1 << 1) | (1 << 5) | (1 << 6) | (1 << 8),
             mode,                                       # g0
             0x1 << 28 | SURF, (5 << 12) | PITCH,        # g1 DST (sel 1)
             0, 0, 0x83E0,                               # g5 back / font / draw
             5,                                          # g6 colour format ARGB1555
             4 << 16 | 3, 5 << 16 | 10]                  # g8 DST xy / wh
    g.run_list(words, [0] * 64)
    check(px1555(ram, SURF, PITCH, 3, 4) == 0x83E0 and px1555(ram, SURF, PITCH, 12, 8) == 0x83E0,
          "command-list fill drew the rectangle through base register 1")
    check(px1555(ram, SURF, PITCH, 2, 4) == 0 and px1555(ram, SURF, PITCH, 13, 4) == 0
          and px1555(ram, SURF, PITCH, 3, 9) == 0, "and nothing outside it")

    # 2. RLE icon 4x2 with colour key: row0 = red, magenta, magenta, white; row1 = 4 x blue
    RLE = 0x110000
    stream = bytes([0x81]) + struct.pack('<H', 0xFC00) + bytes([0x02]) + struct.pack('<H', 0x7C1F) + \
        bytes([0x81]) + struct.pack('<H', 0xFFFF) + bytes([0x04]) + struct.pack('<H', 0x801F)
    ram[RLE:RLE + len(stream)] = np.frombuffer(stream, np.uint8)
    r = regs(x30=(1 << 3) | (1 << 16) | (1 << 20) | (1 << 21), x34=SURF, x38=(5 << 12) | PITCH,
             x3C=20 << 16 | 20, x40=2 << 16 | 4, x50=RLE, x54=(1 << 19) | (5 << 12) | 4, x5C=2 << 16 | 4,
             x84=0x80000000 | 0xFF, x88=0x00F800F8, x8C=0xFFF800F8)
    ram[SURF + 2 * (20 * PITCH + 21):SURF + 2 * (20 * PITCH + 21) + 2] = [0x34, 0x12]   # under the key
    g.run_io(r)
    row0 = [px1555(ram, SURF, PITCH, 20 + i, 20) for i in range(4)]
    row1 = [px1555(ram, SURF, PITCH, 20 + i, 21) for i in range(4)]
    check(row0 == [0xFC00, 0x1234, 0, 0xFFFF] and row1 == [0x801F] * 4,
          f"RLE bitmap decoded across rows, magenta colour-keyed out (row0 {[hex(v) for v in row0]})")

    # 3. text: glyph 4x2 at 4 bpp stored as one big-endian dword F8 00 00 8F; after the byte swap
    #    (8F 00 00 F8) and read high nibble first: row0 = 8 F 0 0, row1 = 0 0 F 8
    FONT, TMP, CLUT, MASK, COL = 0x120000, 0x121000, 0x122000, 0x123000, 0x124000
    ram[FONT:FONT + 4] = [0xF8, 0x00, 0x00, 0x8F]
    # (a) blit 1 dword with SRC byte endian = big -> TMP holds the byte-swapped dword
    g.run_io(regs(x30=1, x34=TMP, x38=(1 << 12) | 1, x40=1 << 16 | 1, x44=FONT,
                  x48=(1 << 23) | (1 << 12) | 1))
    # (b) 4-bit glyph (sub-byte endian 1), stretched x2 into a CLUT4 surface -> A8 mask bytes v * 17
    g.run_io(regs(x30=(1 << 3) | (1 << 21), x34=MASK, x38=(0x0A << 12) | 16, x40=2 << 16 | 16,
                  x50=TMP, x54=(1 << 28) | (1 << 22) | (0x0A << 12) | 8, x5C=2 << 16 | 8))
    swapped = bytes(ram[TMP:TMP + 4])
    mask = bytes(ram[MASK:MASK + 8])
    check(swapped == bytes([0x8F, 0x00, 0x00, 0xF8]), f"big-endian glyph dword byte-swapped ({swapped.hex()})")
    check(mask == bytes([0x88, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x88]),
          f"glyph nibbles read high-first and stretched into A8 alpha ({mask.hex()})")
    # (c) blend a white ARGB1555 PTN over the blue background through the A8 mask (pitch 4, 2 rows)
    ram[COL:COL + 16] = np.frombuffer(struct.pack('<8H', *([0xFFFF] * 8)), np.uint8)
    for i in range(4):
        for j in range(2):
            o = SURF + 2 * ((40 + j) * PITCH + 40 + i)
            ram[o:o + 2] = [0x1F, 0x80]                          # 0x801F blue
    g.run_io(regs(x30=1 | (1 << 3) | (1 << 6) | (2 << 21), x34=SURF, x38=(5 << 12) | PITCH,
                  x3C=40 << 16 | 40, x40=2 << 16 | 4, x44=SURF, x48=(5 << 12) | PITCH, x4C=40 << 16 | 40,
                  x50=COL, x54=(5 << 12) | 4, x5C=2 << 16 | 4, x60=MASK, x64=(0x1D << 12) | 4,
                  x6C=2 << 16 | 4, x84=0xFF))
    top = [px1555(ram, SURF, PITCH, 40 + i, 40) for i in range(4)]
    check(top[1] == 0xFFFF and top[2] == 0x801F and top[3] == 0x801F and top[0] not in (0xFFFF, 0x801F),
          f"font colour blended through the mask: partial / full / none ({[hex(v) for v in top]})")

    # 4. GMA capture: head at 0x130000 -> 64x64 ARGB1555 bitmap at SURF, 4-bit global alpha 0x0F
    HEAD = 0x130000
    head = [0xAA200B51, 0, (PITCH - 1) << 16, (PITCH - 1) << 16, 0, (128 << 16) | 0x0F, 0, SURF, 0, 0]
    ram[HEAD:HEAD + 40] = np.frombuffer(struct.pack('<10I', *head), np.uint8)
    dev = bytearray(0x10000)
    struct.pack_into('<II', dev, 0x6300, 1, HEAD)
    rgb, info = gma_capture.capture(ram, bytes(dev), screen=(64, 64))
    check(info['layers'][0]['enabled'] and len(info['layers'][0]['heads']) == 1, "layer 0 head chain parsed")
    check(tuple(rgb[4, 3]) == (0, 255, 0) and tuple(rgb[0, 0]) == (0, 0, 0) and tuple(rgb[21, 22]) == (0, 0, 255),
          f"capture shows the drawn pixels (green fill {tuple(rgb[4, 3])}, blue icon row {tuple(rgb[21, 22])})")
    check(not g.unsupported, f"no unsupported GE features hit ({dict(g.unsupported)})")

    if fails:
        print(f"\n[FAIL] {len(fails)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] GE model and display capture")
    sys.exit(0)


if __name__ == "__main__":
    main()
