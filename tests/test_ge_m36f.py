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
  4. gma_capture follows layer 0's head pointer to the bitmap and renders it,
  5. a Full HD 1:1 head on a 1080i output is resampled onto the 1280 x 720
     canvas, a 1.5x upscaled 1008 x 640 head placed 1:1,
  6. the S3811's GMA colours, as measured on a real box: a revision-1 head's
     RGB -> YCbCr matrix (all zero: every colour black, alpha still applying)
     and bit 19 of the layer enable register (Cr / Y / Cb taken as they are).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import struct
import time

import numpy as np

import ge_m36f
import gma_capture
import report_artifacts

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
    shot = report_artifacts.path("ge_m36f_capture.png")
    gma_capture.save_png(shot, np.repeat(np.repeat(rgb, 4, axis=0), 4, axis=1))   # 4x for visibility
    report_artifacts.image(shot, "the 64x64 test surface as the GMA layer shows it (4x)")
    check(info['layers'][0]['enabled'] and len(info['layers'][0]['heads']) == 1, "layer 0 head chain parsed")
    check(tuple(rgb[4, 3]) == (0, 255, 0) and tuple(rgb[0, 0]) == (0, 0, 0) and tuple(rgb[21, 22]) == (0, 0, 255),
          f"capture shows the drawn pixels (green fill {tuple(rgb[4, 3])}, blue icon row {tuple(rgb[21, 22])})")
    check(not g.unsupported, f"no unsupported GE features hit ({dict(g.unsupported)})")

    # 5. 1080i (1125-line) output scaling: a native 1920x1080 CLUT8 head is resampled onto 1280x720
    #    (not cropped to 0..1279 x 0..719), while a 1008x640 bitmap upscaled 1.5x by GMA to 1512x960
    #    at (204, 60) is placed 1:1 at (136, 40).
    ram_fhd = np.zeros(0x300000, np.uint8)
    PAL_FHD, HEAD_FHD, BMP_FHD = 0x010000, 0x011000, 0x020000
    struct.pack_into('<II', ram_fhd, PAL_FHD, 0x00FF00FF, 0xFF2080E0)   # idx 0 transparent, idx 1 opaque
    ram_fhd[BMP_FHD + 900 * 1920 + 1500:BMP_FHD + 900 * 1920 + 1506] = 1
    ram_fhd[BMP_FHD + 901 * 1920 + 1500:BMP_FHD + 901 * 1920 + 1506] = 1
    head_fhd = [0xAA2004C1, PAL_FHD, 1919 << 16, 1079 << 16, (1080 << 16) | 1920, (1920 << 16) | 0x0F, 0, BMP_FHD, 0, 0]
    ram_fhd[HEAD_FHD:HEAD_FHD + 40] = np.frombuffer(struct.pack('<10I', *head_fhd), np.uint8)
    dev_fhd = bytearray(0x10000)
    struct.pack_into('<I', dev_fhd, gma_capture.DE_TIMING_REG, 1125 << 16)
    struct.pack_into('<II', dev_fhd, 0x6300, 1, HEAD_FHD)
    rgb_fhd, _ = gma_capture.capture(ram_fhd, bytes(dev_fhd), screen=(1280, 720))
    check(rgb_fhd.shape == (720, 1280, 3) and tuple(rgb_fhd[600, 1000]) == (0x20, 0x80, 0xE0),
          f"Full HD 1920x1080 1:1 GMA head resamples (1500, 900) -> (1000, 600) ({tuple(rgb_fhd[600, 1000])})")

    ram_up = np.zeros(0x200000, np.uint8)
    ram_up[PAL_FHD:PAL_FHD + 8] = ram_fhd[PAL_FHD:PAL_FHD + 8]
    ram_up[BMP_FHD + 500 * 1008 + 900] = 1
    head_up = [0xAA2004C1, PAL_FHD, (1715 << 16) | 204, (1019 << 16) | 60, (640 << 16) | 1008, (1008 << 16) | 0x0F, 0, BMP_FHD, 0, 0]
    ram_up[HEAD_FHD:HEAD_FHD + 40] = np.frombuffer(struct.pack('<10I', *head_up), np.uint8)
    rgb_up, _ = gma_capture.capture(ram_up, bytes(dev_fhd), screen=(1280, 720))
    check(tuple(rgb_up[40 + 500, 136 + 900]) == (0x20, 0x80, 0xE0),
          f"1008x640 GMA head upscaled 1.5x to 1080i maps 1:1 to (136+900, 40+500) ({tuple(rgb_up[540, 1036])})")

    # 6. the S3811's GMA colours (measured on a real box, revision 1): a head block of 0x280 bytes
    #    with an RGB -> YCbCr matrix at +0x240 (12 words x512, rows Y, Cb, Cr of R, G, B, offset;
    #    both originals write BT.709's for HD), which a revision-1 part converts the colours
    #    through -- all zero: every colour black, alpha still applying -- and bit 19 of the layer
    #    enable register, which skips it: the ARGB1555 red, green and blue fields (a CLUT8 palette
    #    entry's bytes 2, 1, 0) taken as Cr, Y, Cb.  Revision 0 shows the RGB as it is.  The TV
    #    decodes the YCbCr as BT.709 on an HD output (or one not set up yet), BT.601 on SD.
    #    Pixels: 0x8000 black, 0xFC00 red, 0xC210 grey (132), 0xC050 (as Cr / Y / Cb: black),
    #    0x7C00 red with alpha 0; palette entry 1: 0xFF20C040 (RGB) and entry 2: 0xFFF0515A (as
    #    Cr / Y / Cb: red), entry 0 transparent.  The background is grey-blue (40, 80, 120), so a
    #    pixel drawn black is told from one not drawn.
    YBIT = 1 << 19
    BT709 = [93, 314, 32, 0, -52, -173, 225, 0, 225, -204, -21, 0, 45]
    BT601 = [131, 258, 50, 0, -76, -149, 225, 0, 225, -188, -37, 0, 45]
    BG = (40, 80, 120)
    ram_y = np.zeros(0x200000, np.uint8)
    PAL_Y, HEAD_A, HEAD_B, BMP_A, BMP_B = 0x010000, 0x011000, 0x011400, 0x020000, 0x030000
    struct.pack_into('<5H', ram_y, BMP_A, 0x8000, 0xFC00, 0xC210, 0xC050, 0x7C00)
    struct.pack_into('<3I', ram_y, PAL_Y, 0x00000000, 0xFF20C040, 0xFFF0515A)
    ram_y[BMP_B:BMP_B + 4] = [1, 1, 2, 0]
    head_a = [0xAA200B51, 0, 4 << 16, 0, (1 << 16) | 5, (10 << 16) | 0x0F, 0, BMP_A, 0, 0]
    head_b = [0xAA200FC1, PAL_Y, (13 << 16) | 10, 0, (1 << 16) | 4, (4 << 16) | 0x0F, 0, BMP_B, 0, 0]

    def capture_y(rev, control, matrix, chained=False, only_b=False, lines=0, bit=YBIT, head_matrix=True):
        a = list(head_a)
        if chained:
            a[6] = HEAD_B
        for addr, words in ((HEAD_A, a), (HEAD_B, head_b)):
            ram_y[addr:addr + 0x280] = 0
            ram_y[addr:addr + 40] = np.frombuffer(struct.pack('<10I', *words), np.uint8)
            ram_y[addr + 0x240:addr + 0x274] = np.frombuffer(struct.pack('<13i', *matrix), np.uint8)
        dev_y = bytearray(0x10000)
        struct.pack_into('<I', dev_y, 0, 0x38110000 | rev)
        # (the output's timing: 0 = not set up, taken as HD; a programmed one would also scale the
        #  heads' positions to the 16 x 2 screen, so only head A at x 0 is checked with PAL)
        struct.pack_into('<I', dev_y, gma_capture.DE_TIMING_REG, lines << 16)
        struct.pack_into('<II', dev_y, 0x6300, control, HEAD_B if only_b else HEAD_A)
        rgb = gma_capture.capture(ram_y, bytes(dev_y), screen=(16, 2), background=BG, ycbcr_bit=bit,
                                  head_matrix=head_matrix)[0]
        return [tuple(int(v) for v in rgb[0, x]) for x in range(16)]

    def close(a, b, tol=1):
        return all(abs(x - y) <= tol for x, y in zip(a, b))

    px = capture_y(0, 1, [0] * 13)                       # revision 0: RGB as it is, matrix or not
    check(px[0] == (0, 0, 0) and px[1] == (255, 0, 0) and px[2] == (132, 132, 132) and px[4] == BG,
          f"revision 0: ARGB1555 shown as RGB, alpha 0 transparent ({px[:5]})")
    px = capture_y(1, 0x40001, [0] * 13)                 # revision 1, the matrix all zero
    check(all(p == (0, 0, 0) for p in px[:4]) and px[4] == BG and px[5] == BG,
          f"revision 1, head matrix all zero: every opaque colour drawn black, alpha 0 still transparent ({px[:6]})")
    px = capture_y(1, 0x40001, BT709)                    # revision 1, the originals' BT.709 matrix (HD)
    check(close(px[0], (0, 0, 0)) and close(px[1], (255, 0, 0)) and close(px[2], (132, 132, 132)) and px[4] == BG,
          f"revision 1, the originals' BT.709 matrix: the RGB colours ({px[:5]})")
    px = capture_y(1, 0x40001, BT601, lines=625)         # an SD output with the originals' SD matrix
    check(close(px[1], (255, 0, 0), 2) and close(px[2], (132, 132, 132)),
          f"revision 1, BT.601 matrix on a PAL output: the RGB colours ({px[:3]})")
    px = capture_y(1, 0x40001, [0] * 13, head_matrix=False)
    check(px[1] == (255, 0, 0), f"a family without the head matrix shows RGB at revision 1 ({px[1]})")
    px = capture_y(1, YBIT | 0x40001, [0] * 13)          # bit 19: no matrix, Cr / Y / Cb (HD: BT.709)
    check(px[0][1] > 60 and px[0][0] < 10 and px[0][2] < 10 and max(px[3]) <= 10 and px[4] == BG,
          f"bit 19: the fields read as Cr / Y / Cb, the matrix skipped (0x8000 green {px[0]}, 0xC050 black {px[3]})")
    px = capture_y(1, YBIT | 0x40001, [0] * 13, lines=625)
    check(px[0][1] > 120 and px[0][0] < 10 and px[0][2] < 10,
          f"bit 19 on a PAL output: decoded as BT.601 (0x8000 {px[0]})")
    px = capture_y(1, YBIT | 0x40001, BT709, bit=0)
    check(close(px[1], (255, 0, 0)), f"a family without the bit: the matrix applies ({px[1]})")
    px = capture_y(1, 0x40001, [0] * 13, only_b=True)    # one CLUT8 head: the fast path
    check(px[10] == (0, 0, 0) and px[12] == (0, 0, 0) and px[13] == BG,
          f"CLUT8, matrix all zero: black, the transparent entry still transparent ({px[10:14]})")
    px = capture_y(1, 0x40001, BT709, only_b=True)
    check(close(px[10], (0x20, 0xC0, 0x40)) and px[13] == BG,
          f"CLUT8 through the BT.709 matrix: palette entry 0xFF20C040 ({px[10]})")
    px = capture_y(1, YBIT | 0x40001, BT709, only_b=True)
    check(px[12][0] > 240 and px[12][1] < 40 and px[12][2] < 10,
          f"CLUT8 under bit 19: entry 0xFFF0515A is Cr F0 / Y 51 / Cb 5A, red ({px[12]})")
    one = capture_y(1, 0x40001, BT709, chained=True)     # two heads: both through render_head
    check(one[1] == capture_y(1, 0x40001, BT709)[1] and one[10] == capture_y(1, 0x40001, BT709, only_b=True)[10],
          f"two chained heads: the same colours ({one[1]}, {one[10]})")
    # a full 1280 x 720 ARGB1555 head through the matrix: the cached table gives the same pixels
    ram_f = np.zeros(0x400000, np.uint8)
    noise = ((np.arange(1280 * 720, dtype=np.uint64) * 2654435761) >> 16).astype(np.uint16)
    ram_f[0x100000:0x100000 + 1280 * 720 * 2] = np.frombuffer(noise.tobytes(), np.uint8)
    head_f = [0xAA200B51, 0, 1279 << 16, 719 << 16, (720 << 16) | 1280, (2560 << 16) | 0x0F, 0, 0x100000, 0, 0]
    ram_f[0x10000:0x10028] = np.frombuffer(struct.pack('<10I', *head_f), np.uint8)
    ram_f[0x10240:0x10274] = np.frombuffer(struct.pack('<13i', *BT709), np.uint8)
    dev_f = bytearray(0x10000)
    struct.pack_into('<I', dev_f, 0, 0x38110001)
    struct.pack_into('<II', dev_f, 0x6300, 0x40001, 0x10000)
    started = time.perf_counter()
    full = gma_capture.capture(ram_f, bytes(dev_f), head_matrix=True)[0]
    took = time.perf_counter() - started
    h = gma_capture.layer_heads(ram_f, bytes(dev_f), matrix=True)[1][0]
    g_f = ge_m36f.GeM36F(ram_f)
    direct = gma_capture._shown_rgba(g_f.decode_rgba_u8(noise.reshape(720, 1280), 5, (5 << 12) | 1280, 0xFF),
                                     dict(h, bt709=True))
    a = direct[..., 3:4].astype(np.float32) / 255.0
    want = np.clip(direct[..., :3].astype(np.float32) * a + 0.5, 0, 255).astype(np.uint8)
    check(int(np.abs(full.astype(int) - want.astype(int)).max()) <= 1,
          f"a 1280 x 720 revision-1 capture through the cached table: the same pixels ({took * 1000:.0f} ms)")

    if fails:
        print(f"\n[FAIL] {len(fails)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] GE model and display capture")
    sys.exit(0)


if __name__ == "__main__":
    main()
