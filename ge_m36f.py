"""Model of the ALi GE_M36F 2D graphics engine (M36xx), registers at 0xB800A000.

The firmware draws its on-screen display (OSD) through this engine.  The
CPU builds GE commands -- register images -- and either loads one into the
live register file and starts it in IO mode (write 1 to +4) or appends many
to a command list in RAM that the engine fetches between the HQ / LQ
start / end pointers (write 2 / 3 to +4).  The engine renders into RAM
surfaces (rectangle fills, frames, bitmap blits with pixel-format
conversion and palette lookup, font glyphs, alpha blending).  The display
layer (GMA, see gma_capture.py) scans one of those surfaces out.  Nothing is
drawn by the CPU writing pixels to a fixed framebuffer address.

Register file (byte offsets; the driver's ge_m36f_lld.o / ge.h):
  +00 ctrl, +04 command (1 IO, 2 HQ, 3 LQ), +08 interrupt status,
  +10/+14 HQ start/end (end = address of the last word), +18/+1C LQ,
  +30 mode:  b0-2 SRC mode, b3-5 PTN type (1 bitmap, 2 font), b6-7 MSK mode,
             b8-10 primitive (1 frame, 2 frame+fill, 3 fill back colour,
             4 fill draw colour / points / lines), b11-15 API primitive,
             b16/17 PTN/MSK RLE, b18 CLUT enable, b19 colour conversion,
             b20 colour key, b21-23 ROP (0 SRC bypass, 1 PTN bypass,
             2 alpha blend, 3 boolean, 4 boolean + alpha blend),
             b24 CLUT mode (0 expansion, 1 correction), b28 clip,
             b29 bitmask, b30 dither, b31 line direction
  entity DST / SRC / PTN / MSK:
             address +34 / +44 / +50 / +60 (b28-31 select base register
             +BC+4*sel), pixel format +38 / +48 / +54 / +64 (b0-11 pitch in
             pixels, b12-16 HW format, b17-18 RGB order, b19 RGB expansion,
             b20/21 scan order, b22 sub-byte endian, b23 byte endian,
             b24 alpha range, b25 alpha polarity, DST b24-31 alpha out,
             PTN b26 font data format, b27 font fill back, b28-29 stretch),
             x | y<<16 +3C / +4C / +58 / +68, w | h<<16 +40 (DST, SRC) /
             +5C / +6C
  +70 bitmask, +74 CLUT control (b0 BT.601/709, b1 matrix, b16-23 unit map,
  b24-25 CLUT RGB order, b31 update), +78 CLUT address, +7C/+80 clip rect
  (b31 outside), +84 alpha control (b0-7 global alpha, b8-11 blend mode,
  b12 global alpha select, b13 bitmap alpha mode, b14 global alpha layer,
  b16-19 boolean op, b20-21 alpha out mode, b30-31 colour key mode),
  +88/+8C colour key range, +90/+94/+98 back / font / draw colour,
  +9C colour format, +A0/+A4 dither seed, +C0..+CC base addresses 1-4.

Command lists: 0x02/0x82 << 24 | group mask loads register groups (GROUPS)
and runs a primitive; 0x81 << 24 | reg << 8 | n writes n words from reg on.
"""
from collections import Counter

import numpy as np

# Register groups of a command-list 0x02 header, in mask-bit order.
GROUPS = ((0x30,), (0x34, 0x38), (0x44, 0x48), (0x50, 0x54), (0x60, 0x64), (0x90, 0x94, 0x98), (0x9C,),
          (0x88, 0x8C), (0x3C, 0x40), (0x4C,), (0x58, 0x5C), (0x68, 0x6C), (0x70,), (0x74, 0x78),
          (0x7C, 0x80), (0x84,), (0xA0, 0xA4))

# HW pixel format -> bits per pixel
BPP = {0x00: 32, 0x01: 32, 0x02: 16, 0x03: 16, 0x04: 16, 0x05: 16, 0x06: 16, 0x07: 16,
       0x08: 2, 0x09: 1, 0x0A: 4, 0x0B: 8, 0x0C: 8, 0x0E: 16,
       0x10: 32, 0x11: 16, 0x13: 32, 0x1C: 1, 0x1D: 8}
CLUT_FORMATS = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E}
ALPHA_FORMATS = {0x1C, 0x1D}
INDEX_FORMATS = CLUT_FORMATS | ALPHA_FORMATS
# HW format -> channel widths in ARGB order (alpha, c1, c2, c3) for packed RGB formats
_PACKED = {0x00: (0, 8, 8, 8), 0x01: (8, 8, 8, 8), 0x02: (0, 4, 4, 4), 0x03: (4, 4, 4, 4),
           0x04: (0, 5, 5, 5), 0x05: (1, 5, 5, 5), 0x06: (0, 5, 6, 5), 0x13: (8, 8, 8, 8), 0x10: (0, 8, 8, 8)}
_YCBCR = {0x10, 0x13}

PHYS_MASK = 0x07FFFFFF


def _u32(v):
    return v & 0xFFFFFFFF


class GeM36F:
    """Executes GE commands on a RAM image (numpy uint8 array, physical address 0 = index 0)."""

    def __init__(self, ram, log=None):
        self.ram = ram
        self.log = log
        self.stats = Counter()          # (api primitive, src mode, ptn type, prim, rop, formats) -> count
        self.unsupported = Counter()
        self.primitives = 0
        self.regs = [0] * 64            # register file of the command-list path (by offset / 4)
        self.trace = None               # set to a list to record the register file of every primitive
        self.trace_limit = 20000

    # ------------------------------------------------------------------
    # entry points
    # ------------------------------------------------------------------
    def run_io(self, regs):
        """IO mode: regs = the 64 words of the live register file."""
        r = list(regs)
        self.execute(r)

    def run_list(self, words, regs):
        """Command list (sequence of uint32 words); regs = live register file
        (base registers +C0..+CC and defaults)."""
        r = self.regs
        for o in range(0xC0, 0xD0, 4):
            r[o >> 2] = regs[o >> 2]
        i, n = 0, len(words)
        while i < n:
            h = int(words[i])
            i += 1
            op = h >> 24
            if op in (0x02, 0x82):
                mask = h & 0xFFFFFF
                for g, rl in enumerate(GROUPS):
                    if mask >> g & 1:
                        for reg in rl:
                            if i >= n:
                                return
                            r[reg >> 2] = int(words[i])
                            i += 1
                self.execute(r)
            elif op == 0x81:
                reg, cnt = (h >> 8) & 0xFF, h & 0xFF
                for k in range(cnt):
                    if i >= n:
                        return
                    r[(reg >> 2) + k & 63] = int(words[i])
                    i += 1
            else:
                self.unsupported[('list header', h)] += 1

    # ------------------------------------------------------------------
    # surfaces
    # ------------------------------------------------------------------
    @staticmethod
    def _addr(r, off):
        v = r[off >> 2]
        sel = v >> 28
        if sel:
            v = r[(0xBC + 4 * sel) >> 2]
        return v & PHYS_MASK

    def _read_raw(self, addr, pfreg, x, y, w, h, rle=False):
        """Raw pixel values (h, w) of a surface region (uint32 / uint16 / uint8)."""
        fmt = (pfreg >> 12) & 0x1F
        pitch = pfreg & 0xFFF
        bpp = BPP.get(fmt, 32)
        if rle:
            return self._read_rle(addr, pfreg, x, y, w, h)
        stride = pitch * bpp // 8
        ram = self.ram
        if bpp >= 8:
            bp = bpp // 8
            rows = []
            for j in range(h):
                a = addr + (y + j) * stride + x * bp
                rows.append(ram[a:a + w * bp])
            buf = np.stack(rows) if rows else np.zeros((0, w * bp), np.uint8)
            if buf.shape[1] != w * bp:          # clipped at the end of RAM
                buf = np.zeros((h, w * bp), np.uint8)
            if bp == 4:
                v = buf.view('<u4') if not (pfreg >> 23) & 1 else buf.view('>u4')
            elif bp == 2:
                v = buf.view('<u2') if not (pfreg >> 23) & 1 else buf.view('>u2')
            else:
                v = buf
            return v.reshape(h, w).copy()
        # sub-byte formats: a linear bitstream (rows need not start on a byte)
        byte, shift = self._subbyte_pos(addr, pfreg, x, y, w, h, bpp)
        ok = byte < ram.size
        vals = np.zeros((h, w), np.uint8)
        vals[ok] = (ram[byte[ok]] >> shift[ok]) & ((1 << bpp) - 1)
        return vals

    @staticmethod
    def _subbyte_pos(addr, pfreg, x, y, w, h, bpp):
        """Byte address and bit shift of every pixel of a sub-byte surface
        region.  Sub-byte endian (bit 22) 0: the left pixel is in the least
        significant bits of a byte; 1: in the most significant bits (font
        glyphs: big-endian dwords, byte-swapped by a blit, then read so)."""
        pitch = pfreg & 0xFFF
        bit = ((np.arange(y, y + h, dtype=np.int64)[:, None] * pitch +
                np.arange(x, x + w, dtype=np.int64)[None, :]) * bpp)
        byte = addr + (bit >> 3)
        if (pfreg >> 22) & 1:
            shift = 8 - bpp - (bit & 7)
        else:
            shift = bit & 7
        return byte, shift.astype(np.uint8)

    def _read_rle(self, addr, pfreg, x, y, w, h):
        """Run-length coded bitmap: a control byte n < 0x80 repeats the next
        pixel n times, n >= 0x80 is followed by n & 0x7F literal pixels; the
        stream runs on across rows (pitch pixels each)."""
        fmt = (pfreg >> 12) & 0x1F
        pitch = pfreg & 0xFFF or w
        bp = max(1, BPP.get(fmt, 32) // 8)
        total = (y + h) * pitch
        ram = self.ram
        out = np.zeros(total, np.uint32)
        i, a, end = 0, addr, min(ram.size, addr + total * (bp + 1) + 16)
        big = (pfreg >> 23) & 1
        while i < total and a < end:
            c = int(ram[a])
            a += 1
            n = c & 0x7F
            if c & 0x80:
                raw = ram[a:a + n * bp]
                a += n * bp
                if bp == 1:
                    v = raw.astype(np.uint32)
                else:
                    v = raw.view(('>' if big else '<') + ('u2' if bp == 2 else 'u4')).astype(np.uint32)
                k = min(n, total - i)
                out[i:i + k] = v[:k]
                i += k
            else:
                raw = ram[a:a + bp]
                a += bp
                v = int.from_bytes(bytes(raw), 'big' if big else 'little')
                k = min(n, total - i)
                out[i:i + k] = v
                i += k
        return out.reshape(y + h, pitch)[y:y + h, x:x + w]

    def _write_raw(self, addr, pfreg, x, y, vals, mask=None):
        fmt = (pfreg >> 12) & 0x1F
        pitch = pfreg & 0xFFF
        bpp = BPP.get(fmt, 32)
        stride = pitch * bpp // 8
        h, w = vals.shape
        ram = self.ram
        if bpp >= 8:
            bp = bpp // 8
            dt = {4: '<u4', 2: '<u2', 1: 'u1'}[bp]
            if bp > 1 and (pfreg >> 23) & 1:
                dt = dt.replace('<', '>')
            v = vals.astype(dt)
            for j in range(h):
                a = addr + (y + j) * stride + x * bp
                if a < 0 or a + w * bp > ram.size:
                    continue
                row = ram[a:a + w * bp].view(dt)
                if mask is None:
                    row[:] = v[j]
                else:
                    m = mask[j]
                    row[m] = v[j][m]
            return
        byte, shift = self._subbyte_pos(addr, pfreg, x, y, w, h, bpp)
        pm = (1 << bpp) - 1
        sel = byte < ram.size
        if mask is not None:
            sel &= mask
        byte, shift, v = byte[sel], shift[sel].astype(np.int64), vals[sel].astype(np.int64)
        for b, s, val in zip(byte.tolist(), shift.tolist(), v.tolist()):     # several pixels share a byte
            ram[b] = (int(ram[b]) & ~(pm << s)) | ((val & pm) << s)

    # ------------------------------------------------------------------
    # pixel formats
    # ------------------------------------------------------------------
    @staticmethod
    def _expand(c, bits, zero_pad=False):
        if bits == 8:
            return c.astype(np.float32)
        if bits == 0:
            return None
        c = c.astype(np.uint32)
        if zero_pad and bits > 1:
            return (c << (8 - bits)).astype(np.float32)
        out = (c << (8 - bits)) | (c >> max(0, 2 * bits - 8)) if bits >= 4 else c * (255 // ((1 << bits) - 1))
        return out.astype(np.float32)

    def _decode(self, raw, fmt, pfreg, clut=None):
        """raw values -> float32 (h, w, 4) in A, R, G, B order."""
        h, w = raw.shape
        out = np.empty((h, w, 4), np.float32)
        order = (pfreg >> 17) & 3
        if fmt in _PACKED:
            wa, w1, w2, w3 = _PACKED[fmt]
            if order in (2, 3):             # RGBA / BGRA: alpha in the low bits
                widths = (w1, w2, w3, wa)
            else:
                widths = (wa, w1, w2, w3)
            v = raw.astype(np.uint32)
            total = sum(widths)
            chans = []
            sh = total
            for wd in widths:
                sh -= wd
                chans.append((v >> sh) & ((1 << wd) - 1) if wd else None)
            if order in (2, 3):
                c1, c2, c3, a = chans
                aw = widths[3]
            else:
                a, c1, c2, c3 = chans
                aw = widths[0]
            zp = bool((pfreg >> 19) & 1)
            e1, e2, e3 = self._expand(c1, w1, zp), self._expand(c2, w2, zp), self._expand(c3, w3, zp)
            if order in (1, 3):             # ABGR / BGRA
                e1, e3 = e3, e1
            out[..., 1], out[..., 2], out[..., 3] = e1, e2, e3
            if a is None:
                out[..., 0] = 255.0
            else:
                av = self._expand(a, aw)
                if (pfreg >> 24) & 1 and aw == 8:   # alpha range 0..127
                    av = np.minimum(av * 2.0, 255.0)
                if (pfreg >> 25) & 1:
                    av = 255.0 - av
                out[..., 0] = av
            if fmt in _YCBCR:
                out[..., 1:] = self._ycbcr_to_rgb(out[..., 1:], 0)
            return out
        if fmt in CLUT_FORMATS:
            if fmt == 0x0E:                 # ACLUT88: alpha high byte, index low byte
                idx = raw.astype(np.uint32) & 0xFF
                alpha = (raw.astype(np.uint32) >> 8).astype(np.float32)
            elif fmt == 0x0B:               # ACLUT44
                idx = raw.astype(np.uint32) & 0xF
                alpha = ((raw.astype(np.uint32) >> 4) * 17).astype(np.float32)
            else:
                idx = raw.astype(np.uint32)
                alpha = None
            if clut is None:
                g = idx.astype(np.float32)
                out[..., 0] = 255.0
                out[..., 1] = out[..., 2] = out[..., 3] = g
            else:
                out[:] = clut[np.minimum(idx, clut.shape[0] - 1)]
            if alpha is not None:
                out[..., 0] = alpha
            return out
        if fmt == 0x1D:
            out[..., 0] = raw.astype(np.float32)
            out[..., 1:] = 255.0
            return out
        if fmt == 0x1C:
            out[..., 0] = raw.astype(np.float32) * 255.0
            out[..., 1:] = 255.0
            return out
        self.unsupported[('decode format', fmt)] += 1
        out[...] = 0
        return out

    def _encode(self, px, fmt, pfreg):
        """float32 (h, w, 4) A, R, G, B -> raw values for format fmt."""
        p = np.clip(px + 0.5, 0, 255).astype(np.uint32)
        a, r, g, b = p[..., 0], p[..., 1], p[..., 2], p[..., 3]
        order = (pfreg >> 17) & 3
        if fmt in _PACKED:
            if fmt in _YCBCR:
                ycc = self._rgb_to_ycbcr(px[..., 1:], 0)
                ycc = np.clip(ycc + 0.5, 0, 255).astype(np.uint32)
                r, g, b = ycc[..., 0], ycc[..., 1], ycc[..., 2]
            if (pfreg >> 25) & 1:
                a = 255 - a
            if (pfreg >> 24) & 1:
                a = a >> 1
            wa, w1, w2, w3 = _PACKED[fmt]
            if order in (1, 3):
                r, b = b, r
            c = [(a >> (8 - wa)) if wa else None, r >> (8 - w1), g >> (8 - w2), b >> (8 - w3)]
            if order in (2, 3):
                seq = [(c[1], w1), (c[2], w2), (c[3], w3), (c[0], wa)]
            else:
                seq = [(c[0], wa), (c[1], w1), (c[2], w2), (c[3], w3)]
            v = np.zeros(a.shape, np.uint32)
            for cv, wd in seq:
                if wd:
                    v = (v << wd) | (cv & ((1 << wd) - 1))
            return v
        if fmt == 0x1D:
            return a
        if fmt == 0x1C:
            return (a >= 128).astype(np.uint32)
        self.unsupported[('encode format', fmt)] += 1
        return np.zeros(a.shape, np.uint32)

    @staticmethod
    def _ycbcr_to_rgb(ycc, bt709):
        y, cb, cr = ycc[..., 0] - 16.0, ycc[..., 1] - 128.0, ycc[..., 2] - 128.0
        if bt709:
            r = 1.164 * y + 1.793 * cr
            g = 1.164 * y - 0.213 * cb - 0.533 * cr
            b = 1.164 * y + 2.112 * cb
        else:
            r = 1.164 * y + 1.596 * cr
            g = 1.164 * y - 0.392 * cb - 0.813 * cr
            b = 1.164 * y + 2.017 * cb
        return np.clip(np.stack([r, g, b], -1), 0, 255)

    @staticmethod
    def _rgb_to_ycbcr(rgb, bt709):
        r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
        if bt709:
            y = 16 + 0.183 * r + 0.614 * g + 0.062 * b
            cb = 128 - 0.101 * r - 0.339 * g + 0.439 * b
            cr = 128 + 0.439 * r - 0.399 * g - 0.040 * b
        else:
            y = 16 + 0.257 * r + 0.504 * g + 0.098 * b
            cb = 128 - 0.148 * r - 0.291 * g + 0.439 * b
            cr = 128 + 0.439 * r - 0.368 * g - 0.071 * b
        return np.stack([y, cb, cr], -1)

    def _clut(self, r, n):
        """Palette (n, 4) float32 A, R, G, B from the CLUT address."""
        addr = r[0x78 >> 2] & PHYS_MASK & ~7
        ctl = r[0x74 >> 2]
        ram = self.ram
        n = max(2, n)
        raw = ram[addr:addr + 4 * n]
        if raw.size != 4 * n:
            return None
        v = raw.view('<u4').reshape(1, n)
        pal = self._decode(v, 0x01, ((ctl >> 24) & 3) << 17)[0]
        return pal

    # ------------------------------------------------------------------
    # one primitive
    # ------------------------------------------------------------------
    def execute(self, r):
        if self.trace is not None and len(self.trace) < self.trace_limit:
            self.trace.append(list(r))
        try:
            self._execute(r)
        except Exception as e:          # never take the emulation down
            self.unsupported[('exception', type(e).__name__, str(e)[:80])] += 1

    def _execute(self, r):
        m = r[0x30 >> 2]
        src_mode = m & 7
        ptn_type = (m >> 3) & 7
        msk_mode = (m >> 6) & 3
        prim = (m >> 8) & 7
        api = (m >> 11) & 0x1F
        clut_en = (m >> 18) & 1
        cc_en = (m >> 19) & 1
        ckey_en = (m >> 20) & 1
        rop = (m >> 21) & 7
        clip_en = (m >> 28) & 1
        bmask_en = (m >> 29) & 1

        dst_pf = r[0x38 >> 2]
        dst_fmt = (dst_pf >> 12) & 0x1F
        dst = self._addr(r, 0x34)
        dxy = r[0x3C >> 2]
        dx, dy = dxy & 0xFFF, (dxy >> 16) & 0xFFF
        dwh = r[0x40 >> 2]
        w, h = dwh & 0xFFF, (dwh >> 16) & 0xFFF
        if api in (9, 11):              # points
            w = h = 1
        src_pf = r[0x48 >> 2]
        ptn_pf = r[0x54 >> 2]
        ptn_fmt = (ptn_pf >> 12) & 0x1F
        src_fmt = (src_pf >> 12) & 0x1F
        key = (api, src_mode, ptn_type, prim, rop, clut_en, cc_en, ckey_en, msk_mode, bmask_en, clip_en,
               dst_fmt, src_fmt if src_mode else None, ptn_fmt if ptn_type else None)
        self.stats[key] += 1
        self.primitives += 1
        if w == 0 or h == 0 or dst == 0:
            return
        if w * h > 4096 * 2048:
            self.unsupported[('huge', w, h)] += 1
            return

        # write mask (clip rectangle)
        wmask = None
        if clip_en:
            c0, c1 = r[0x7C >> 2], r[0x80 >> 2]
            cx0, cy0 = c0 & 0xFFF, (c0 >> 16) & 0xFFF
            cx1, cy1 = c1 & 0xFFF, (c1 >> 16) & 0xFFF
            xs = np.arange(dx, dx + w)[None, :]
            ys = np.arange(dy, dy + h)[:, None]
            inside = (xs >= cx0) & (xs <= cx1) & (ys >= cy0) & (ys <= cy1)
            wmask = ~inside if (c0 >> 31) & 1 else inside

        index_domain = dst_fmt in INDEX_FORMATS and not (clut_en and dst_fmt not in INDEX_FORMATS)
        col_fmt = r[0x9C >> 2] & 0x1F

        # ---------------- PTN (foreground) ----------------
        ptn = None          # raw (index domain) or float (h, w, 4)
        ptn_raw = None
        pmask = None        # pixels the PTN covers (fonts, frames)
        if ptn_type == 1:   # bitmap
            p_addr = self._addr(r, 0x50)
            pxy = r[0x58 >> 2]
            px, py = pxy & 0xFFF, (pxy >> 16) & 0xFFF
            pwh = r[0x5C >> 2]
            pw, ph = pwh & 0xFFF, (pwh >> 16) & 0xFFF
            if (pw, ph) != (w, h) and pw and ph and api == 13:
                self.unsupported[('scaling',)] += 1
            sx, sy = (ptn_pf >> 28) & 1, (ptn_pf >> 29) & 1      # pixel replication x2
            raw = self._read_raw(p_addr, ptn_pf, px, py, (w + sx) >> sx, (h + sy) >> sy, rle=(m >> 16) & 1)
            if sx:
                raw = np.repeat(raw, 2, axis=1)[:, :w]
            if sy:
                raw = np.repeat(raw, 2, axis=0)[:h]
            ptn_raw = raw
            if index_domain and ptn_fmt in INDEX_FORMATS and not clut_en:
                ptn = raw.astype(np.uint32)
            else:
                clut = self._clut(r, 1 << min(8, BPP.get(ptn_fmt, 8))) if (clut_en and ptn_fmt in CLUT_FORMATS) else None
                ptn = self._decode(raw, ptn_fmt, ptn_pf, clut)
                if cc_en and clut is not None:
                    ctl = r[0x74 >> 2]
                    ptn[..., 1:] = self._ycbcr_to_rgb(ptn[..., 1:], ctl & 1)
        elif ptn_type == 2:  # font
            p_addr = self._addr(r, 0x50)
            pxy = r[0x58 >> 2]
            px, py = pxy & 0xFFF, (pxy >> 16) & 0xFFF
            sx, sy = (ptn_pf >> 28) & 1, (ptn_pf >> 29) & 1
            fw, fh = (w + sx) >> sx, (h + sy) >> sy
            raw = self._read_raw(p_addr, ptn_pf, px, py, fw, fh)
            if sx:
                raw = np.repeat(raw, 2, axis=1)[:, :w]
            if sy:
                raw = np.repeat(raw, 2, axis=0)[:h]
            fill_back = api == 6 or (ptn_pf >> 27) & 1
            if ptn_fmt == 0x1D:
                alpha = raw.astype(np.float32)
            elif ptn_fmt in (0x1C, 0x09):
                alpha = raw.astype(np.float32) * 255.0
            else:
                bits = BPP.get(ptn_fmt, 1)
                alpha = raw.astype(np.float32) * (255.0 / ((1 << bits) - 1))
            fg = r[0x94 >> 2]
            bg = r[0x90 >> 2]
            if index_domain:
                on = alpha >= 128
                ptn = np.where(on, fg, bg).astype(np.uint32)
                pmask = None if fill_back else on
            else:
                fgc = self._decode(np.array([[fg]], np.uint32), col_fmt, 0)[0, 0]
                bgc = self._decode(np.array([[bg]], np.uint32), col_fmt, 0)[0, 0]
                t = (alpha / 255.0)[..., None]
                if fill_back:
                    ptn = fgc * t + bgc * (1 - t)
                    ptn[..., 0] = fgc[0] * t[..., 0] + bgc[0] * (1 - t[..., 0])
                else:
                    ptn = np.empty((h, w, 4), np.float32)
                    ptn[...] = fgc
                    ptn[..., 0] = fgc[0] * t[..., 0]
                    if rop != 2 and rop != 4:
                        pmask = alpha >= 128
        elif prim:
            back, draw = r[0x90 >> 2], r[0x98 >> 2]
            if prim in (1, 2) or api in (1, 2):
                frame = np.zeros((h, w), bool)
                frame[0, :] = frame[-1, :] = True
                frame[:, 0] = frame[:, -1] = True
            if index_domain:
                if prim == 3:
                    ptn = np.full((h, w), back, np.uint32)
                elif prim == 4 or prim == 0:
                    ptn = np.full((h, w), draw, np.uint32)
                elif prim == 1:
                    ptn = np.full((h, w), draw, np.uint32)
                    pmask = frame
                else:
                    ptn = np.where(frame, draw, back).astype(np.uint32)
            else:
                bc = self._decode(np.array([[back]], np.uint32), col_fmt, 0)[0, 0]
                dc = self._decode(np.array([[draw]], np.uint32), col_fmt, 0)[0, 0]
                ptn = np.empty((h, w, 4), np.float32)
                if prim == 3:
                    ptn[...] = bc
                elif prim == 1:
                    ptn[...] = dc
                    pmask = frame
                elif prim == 2:
                    ptn[...] = bc
                    ptn[frame] = dc
                else:
                    ptn[...] = dc

        # ---------------- SRC (background) ----------------
        src = None
        if src_mode in (1, 2) or (rop in (0, 2, 3, 4) and src_mode == 0 and ptn is None):
            s_addr = self._addr(r, 0x44) or dst
            sxy = r[0x4C >> 2]
            if sxy == 0x0FFF0FFF:
                sxy = dxy
            sx_, sy_ = sxy & 0xFFF, (sxy >> 16) & 0xFFF
            s_pf = src_pf if (src_pf & 0xFFF) else dst_pf
            s_fmt = (s_pf >> 12) & 0x1F
            raw = self._read_raw(s_addr, s_pf, sx_, sy_, w, h)
            if index_domain and s_fmt in INDEX_FORMATS:
                src = raw.astype(np.uint32)
            else:
                clut = self._clut(r, 256) if (clut_en and s_fmt in CLUT_FORMATS and ptn_type != 1) else None
                src = self._decode(raw, s_fmt, s_pf, clut)
        elif src_mode in (3, 4):        # fill with the back colour
            back = r[0x90 >> 2]
            if index_domain:
                src = np.full((h, w), back, np.uint32)
            else:
                src = np.empty((h, w, 4), np.float32)
                src[...] = self._decode(np.array([[back]], np.uint32), col_fmt, 0)[0, 0]

        need_dst = rop in (2, 3, 4) or ckey_en or bmask_en
        if src is None and need_dst:
            raw = self._read_raw(dst, dst_pf, dx, dy, w, h)
            src = raw.astype(np.uint32) if index_domain else self._decode(raw, dst_fmt, dst_pf)

        # ---------------- MSK ----------------
        malpha = None       # per-pixel alpha factor 0..1 for blending (MSK A8)
        if msk_mode:
            m_pf = r[0x64 >> 2]
            m_fmt = (m_pf >> 12) & 0x1F
            mxy = r[0x68 >> 2]
            mraw = self._read_raw(self._addr(r, 0x60), m_pf, mxy & 0xFFF, (mxy >> 16) & 0xFFF, w, h,
                                  rle=(m >> 17) & 1)
            if m_fmt == 0x1C or BPP.get(m_fmt, 8) == 1:
                shape = mraw != 0
                pmask = shape if pmask is None else (pmask & shape)
            else:
                bits = min(8, BPP.get(m_fmt, 8))
                malpha = (mraw.astype(np.uint32) & ((1 << bits) - 1)).astype(np.float32) / float((1 << bits) - 1)
                if (m_pf >> 25) & 1:
                    malpha = 1.0 - malpha
                if rop not in (2, 4):
                    shape = malpha >= 0.5
                    pmask = shape if pmask is None else (pmask & shape)

        # ---------------- ROP ----------------
        out = None
        if rop == 0:
            out = src if src is not None else ptn
        elif rop == 1:
            out = ptn if ptn is not None else src
        elif rop in (2, 4) and not index_domain:
            out = self._blend(r, ptn, src, w, h, malpha)
        elif rop in (3, 4) or (rop == 2 and index_domain):
            out = self._bool(r, ptn, src, index_domain, dst_fmt, dst_pf)
        if out is None:
            self.unsupported[('nothing to draw', key)] += 1
            return

        # colour key (A84 b30-31: 0 DST key -- the keyed colours in SRC (== DST)
        # are kept; 1 / 2 PTN key after / before the CLUT -- keyed PTN colours
        # are not written).  The range registers hold A, R, G, B bytes.
        if ckey_en and (ptn is not None or src is not None):
            lo, hi = r[0x88 >> 2], r[0x8C >> 2]
            ck_mode = (r[0x84 >> 2] >> 30) & 3
            if ck_mode == 0:
                cv = self._read_raw(dst, dst_pf, dx, dy, w, h)
                cfmt, cpf = dst_fmt, dst_pf
            elif ck_mode == 2 and ptn_raw is not None and ptn_fmt in CLUT_FORMATS:
                cv = ptn_raw
                cfmt, cpf = None, None
            else:
                cv = ptn
                cfmt, cpf = 'decoded', None
            if index_domain or cfmt is None or (cfmt != 'decoded' and cfmt in INDEX_FORMATS):
                cv = np.asarray(cv).astype(np.uint32) if np.asarray(cv).ndim == 2 else self._encode(cv, dst_fmt, dst_pf)
                hit = (cv >= (lo & 0xFF if cfmt is None else lo)) & (cv <= (hi & 0xFF if cfmt is None else hi))
            else:
                c = cv if cfmt == 'decoded' else self._decode(cv, cfmt, cpf)
                c = np.clip(c + 0.5, 0, 255).astype(np.int32)
                hit = np.ones((h, w), bool)
                for ch, sh in enumerate((24, 16, 8, 0)):
                    hit &= (c[..., ch] >= ((lo >> sh) & 0xFF)) & (c[..., ch] <= ((hi >> sh) & 0xFF))
            pm = ~hit           # keyed pixels are not written
            pmask = pm if pmask is None else (pmask & pm)

        if pmask is not None:
            wmask = pmask if wmask is None else (wmask & pmask)

        if index_domain:
            vals = out.astype(np.uint32) if not isinstance(out, np.ndarray) or out.ndim == 2 else self._encode(out, dst_fmt, dst_pf)
        else:
            if out.ndim == 2:
                out = self._decode(out, dst_fmt, dst_pf)
            mode = (r[0x84 >> 2] >> 20) & 3
            if mode == 3:               # alpha out from register
                out = out.copy()
                out[..., 0] = (dst_pf >> 24) & 0xFF
            vals = self._encode(out, dst_fmt, dst_pf)
        if bmask_en:
            bm = r[0x70 >> 2]
            old = self._read_raw(dst, dst_pf, dx, dy, w, h).astype(np.uint32)
            vals = (vals & bm) | (old & ~np.uint32(bm))
        self._write_raw(dst, dst_pf, dx, dy, vals, wmask)

    def _blend(self, r, ptn, src, w, h, malpha=None):
        """Alpha blending of PTN (foreground) over SRC (background); malpha:
        per-pixel alpha factor from an A8 MSK."""
        if ptn is None:
            return src
        ac = r[0x84 >> 2]
        galpha = (ac & 0xFF) / 255.0
        bmode = (ac >> 8) & 0xF
        gsel = (ac >> 12) & 1
        out_mode = (ac >> 20) & 3
        p = ptn.astype(np.float32)
        if src is None:
            src = np.zeros_like(p)
        s = src.astype(np.float32)
        pa = p[..., 0] / 255.0
        if gsel:                        # global alpha only
            pa = np.full_like(pa, galpha)
        else:
            pa = pa * galpha
        if malpha is not None:
            pa = pa * malpha
        sa = s[..., 0] / 255.0
        if bmode not in (0,):
            self.unsupported[('blend mode', bmode)] += 1
        res = np.empty_like(p)
        k = pa[..., None]
        res[..., 1:] = p[..., 1:] * k + s[..., 1:] * (1.0 - k)
        if out_mode == 1:
            res[..., 0] = s[..., 0]
        elif out_mode == 2:
            res[..., 0] = p[..., 0]
        else:
            res[..., 0] = (pa + sa * (1.0 - pa)) * 255.0
        return res

    def _bool(self, r, ptn, src, index_domain, dst_fmt, dst_pf):
        op = (r[0x84 >> 2] >> 16) & 0xF
        if index_domain:
            a = ptn if ptn is not None else src
            b = src if src is not None else a
            a = a.astype(np.uint32)
            b = b.astype(np.uint32)
        else:
            a = self._encode(ptn, dst_fmt, dst_pf) if ptn is not None else None
            b = self._encode(src, dst_fmt, dst_pf) if src is not None else a
            if a is None:
                a = b
        na, nb = ~a, ~b
        res = {0: a & 0, 1: a & b, 2: a & nb, 3: b, 4: na & b, 5: a, 6: a ^ b, 7: a | b, 8: ~(a | b),
               9: a ^ nb, 10: na, 11: na | b, 12: nb, 13: a | nb, 14: ~(a & b), 15: ~(a & 0)}[op]
        res = res & np.uint32(0xFFFFFFFF)
        if index_domain:
            return res
        return self._decode(res, dst_fmt, dst_pf)
