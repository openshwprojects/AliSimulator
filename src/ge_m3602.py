"""
The M3602's graphics engine (registers at 0xB800C000), which the Ferguson
Ariva T50 draws its OSD with.  Its driver is the SDK's ge_hal.c in
libcore_hd.a (the T50's ge_hal_blt is the same 0xCF8 bytes): it builds a
command in RAM and starts the engine on it -- an older engine than the
M3801's GE_M36F (ge_m36f.py), which the other M36xx boards' firmwares use at
0xB800A000.

  +0x00  control: the driver writes 0x10, then 2 (start), then 0
  +0x04  reads 0 while the engine is idle
  +0x08  status: bit 1 once the commands are done (write 1 to clear)
  +0x0C  bits 24..27 of the first command's address
  +0x10  its bits 0..23 | its section mask << 24

The model runs the commands at the start and sets status bit 1, which the
T50's driver polls (its device's polling flag is set: no interrupt).

A command (ge_hal_blt builds it, handle_cmd chains a command given while
the engine is busy to the one before):
  w0      the next command: address bits 0..23 | its section mask << 24 (0: none)
  w1      control: bits 3..4 how source 2 is read (1 a bitmap, 2 a constant
          colour), bit 6 CLUT, bit 7 resize, bit 9 clip, bits 16..18 how the
          sources combine (1: source 2 alone)
  w2      the destination's address
  w4      x | y << 16 in the destination
  w5      its pitch in bytes | its pixel format << 16 (the SDK's
          GE_PIXEL_FORMAT: 0x0B CLUT8, 0x15 AYCbCr8888, ...)
  w6, w7  (parameters the control word marks)
  then the sections of the mask, in this order:
    bit 7  2 words
    bit 0  source 1, 6 words: address, second address, x | y << 16,
           pitch | format << 16, (width - 1) | (height - 1) << 16 -- the
           size of the destination rectangle -- and a colour
    bit 1  source 2, the same: the bitmap read, or (word 5) the colour a
           fill writes
    bit 3  resize, 4 words: filter modes, the horizontal | vertical step
           << 16 in 1/8192 source pixels per destination pixel, the two
           filters' coefficient tables
    bit 4  flicker filter, 4 words
    bit 2  CLUT / colour conversion, 2 words: mode (bit 18: the CLUT is on),
           the palette's address
    bit 6  clip, 2 words: x0 | y0 << 16 (bit 31: draw inside the
           rectangle), x1 | y1 << 16
    bit 5  colour key and blending, 3 words

What the T50's OSD driver (the SDK's osd_s3601) gives it is modelled: fills,
copies, and the scaled copies of its 912 x 640 CLUT8 screen into the
AYCbCr8888 bitmap the display layer shows -- source 2 into the destination
rectangle, through the palette when the CLUT is on, sampled at the resize
steps (the nearest pixel: no filter), inside the clip rectangle.  Other ways
of combining the sources are drawn as that copy and counted in unsupported.
"""
import struct

import numpy as np
from numpy.lib.stride_tricks import as_strided

BASE = 0xC000                          # in the device window 0xB8000000
BPP = {0x00: 2, 0x02: 2, 0x03: 2, 0x04: 2, 0x05: 4, 0x06: 2, 0x07: 2, 0x0B: 1, 0x0C: 2, 0x15: 4, 0x19: 1}
DTYPE = {1: np.uint8, 2: '<u2', 4: '<u4'}
# (mask bit, words) of the sections, in the order they follow the 8-word header
SECTIONS = ((7, 2), (0, 6), (1, 6), (3, 4), (4, 4), (2, 2), (6, 2), (5, 3))
SRC1, SRC2, CLUT, RESIZE, CLIP = 0, 1, 2, 3, 6
MAX_COMMANDS = 4096                     # a chain longer than this is taken as a loop


class GeM3602:
    def __init__(self, sim):
        self.sim = sim
        self.commands = 0
        self.unsupported = {}
        self._ram = None
        sim._mmio_on('w', self._write_control, BASE, BASE + 3)
        sim._mmio_on('w', self._write_status, BASE + 8, BASE + 0xB)

    def _rd(self, offset):
        return int.from_bytes(self.sim.peek(0xB8000000 + BASE + offset, 4), 'little')

    def _write_control(self, uc, access, address, size, value, user_data):
        if address & 3 or size != 4 or value != 2:
            return None
        lo = self._rd(0x10)
        first = (self._rd(0x0C) & 0xF) << 24 | lo & 0xFFFFFF
        self.sim.ge_ops += 1
        if self.sim.ge_render:
            self.run(first, lo >> 24)
        self.sim.poke(0xB8000000 + BASE + 8, struct.pack("<I", self._rd(8) | 2))
        self.sim.poke(0xB8000000 + BASE + 4, bytes(4))
        return None

    def _write_status(self, uc, access, address, size, value, user_data):
        if address & 3 or size != 4:
            return None
        return self._rd(8) & ~value & 0xFFFFFFFF

    def _note(self, what):
        self.unsupported[what] = self.unsupported.get(what, 0) + 1

    @property
    def ram(self):
        if self._ram is None:
            self._ram = np.frombuffer(self.sim.ram_buffer, dtype=np.uint8, count=self.sim.ram_size)
        return self._ram

    def _rect(self, address, pitch, rows, bpp, width):
        """The RAM's rows of width pixels from address (physical) on, pitch bytes apart, as a writable view
        of bpp-byte pixels; None when they leave the RAM."""
        a = address % self.sim.ram_size
        if rows <= 0 or width <= 0 or a + (rows - 1) * pitch + width * bpp > self.ram.size:
            return None
        return as_strided(self.ram[a:], shape=(rows, width * bpp), strides=(pitch, 1)).view(DTYPE[bpp])

    def run(self, address, mask):
        """Run the command at address (physical) and the ones chained to it."""
        for _ in range(MAX_COMMANDS):
            a = address % self.sim.ram_size
            if a + 40 * 4 > self.ram.size:
                return
            words = self.ram[a:a + 40 * 4].view('<u4').tolist()
            self.commands += 1
            self._execute(words, mask)
            link = words[0]
            if not link:
                return
            address, mask = address & 0x0F000000 | link & 0xFFFFFF, link >> 24

    def _execute(self, w, mask):
        sec, i = {}, 8
        for bit, n in SECTIONS:
            if mask >> bit & 1:
                sec[bit] = w[i:i + n]
                i += n
        if SRC1 not in sec:
            self._note("no source 1 (no rectangle)")
            return
        ctrl = w[1]
        if (ctrl >> 16) & 7 != 1:
            self._note(f"combine mode {(ctrl >> 16) & 7}")
        size = sec[SRC1][4]
        width, height = (size & 0xFFFF) + 1, (size >> 16) + 1
        dfmt = (w[5] >> 16) & 0x1F
        dpitch = w[5] & 0xFFFF
        dbpp = BPP.get(dfmt)
        if dbpp is None:
            self._note(f"destination format 0x{dfmt:02X}")
            return
        dx, dy = w[4] & 0xFFFF, w[4] >> 16
        palette = None
        if CLUT in sec and sec[CLUT][0] >> 18 & 1:
            p = sec[CLUT][1] % self.sim.ram_size
            if p + 1024 <= self.ram.size:
                palette = self.ram[p:p + 1024].view('<u4')
        mode = (ctrl >> 3) & 3
        src = sec.get(SRC2)
        if mode == 2 and src is not None:                   # a constant colour
            colour = src[5]
            sfmt = (src[3] >> 16) & 0x1F
            if palette is not None and sfmt == 0x0B and dbpp == 4:
                colour = int(palette[colour & 0xFF])
            pixels = np.full((height, width), colour & ((1 << (8 * dbpp)) - 1), dtype=DTYPE[dbpp])
        elif mode == 1 and src is not None:                 # a bitmap
            pixels = self._read_source(src, width, height, sec.get(RESIZE), palette, dbpp)
            if pixels is None:
                return
        else:
            self._note(f"source 2 mode {mode}")
            return
        self._write(w[2], dpitch, dbpp, dx, dy, pixels, sec.get(CLIP))

    def _read_source(self, src, width, height, resize, palette, dbpp):
        sfmt, spitch = (src[3] >> 16) & 0x1F, src[3] & 0xFFFF
        sbpp = BPP.get(sfmt)
        if sbpp is None:
            self._note(f"source format 0x{sfmt:02X}")
            return None
        sx, sy = src[2] & 0xFFFF, src[2] >> 16
        sw, sh = (src[4] & 0xFFFF) + 1, (src[4] >> 16) + 1
        if resize is not None:
            hstep, vstep = resize[1] & 0xFFFF, resize[1] >> 16
            cols = np.minimum((np.arange(width) * hstep) >> 13, sw - 1)
            rows = np.minimum((np.arange(height) * vstep) >> 13, sh - 1)
        else:
            cols = np.minimum(np.arange(width), sw - 1)
            rows = np.minimum(np.arange(height), sh - 1)
        block = self._rect(src[0] + sy * spitch + sx * sbpp, spitch, sh, sbpp, sw)
        if block is None:
            self._note("source outside the RAM")
            return None
        pixels = block[rows][:, cols]
        if palette is not None and sfmt == 0x0B:
            pixels = palette[pixels]
            sbpp = 4
        if sbpp != dbpp:
            self._note(f"format 0x{sfmt:02X} to {8 * dbpp} bits")
            pixels = pixels.astype(np.uint64) & ((1 << (8 * dbpp)) - 1)
        return pixels.astype(DTYPE[dbpp])

    def _write(self, address, pitch, bpp, x, y, pixels, clip):
        height, width = pixels.shape
        keep = None
        if clip is not None:
            c0, c1 = clip
            xs, ys = x + np.arange(width), y + np.arange(height)
            keep = (((xs >= (c0 & 0x7FFF)) & (xs <= (c1 & 0x7FFF)))[None, :] &
                    ((ys >= (c0 >> 16 & 0x7FFF)) & (ys <= (c1 >> 16 & 0x7FFF)))[:, None])
            if not c0 >> 31:
                keep = ~keep
        width = min(width, pitch // bpp - x)
        rows = self._rect(address + y * pitch + x * bpp, pitch, height, bpp, width)
        if rows is None:
            self._note("destination outside the RAM")
            return
        out = pixels[:, :width]
        if keep is None:
            rows[...] = out
        else:
            k = keep[:, :width]
            rows[k] = out[k]
