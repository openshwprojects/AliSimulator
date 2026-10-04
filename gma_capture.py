"""Screen capture of the ALi M36F display layer (GMA) -- what the OSD shows.

The display engine has no fixed framebuffer.  Each GMA layer has an enable
register and a "base address" register (layer 0: 0xB8006300 / 0xB8006304)
holding the physical address of the first hardware region head in RAM; heads
are chained.  A head (0x28 bytes, filled by gma_m36f_lld's gma_block_create /
gma_m36f_init_head / gma_fill_hw_head) is:
  +00  b0 enable, b4-7 pixel format (GE HW code: 0x0C CLUT8, 0x01 ARGB8888,
       0x03 ARGB4444, 0x05 ARGB1555, 0x06 RGB565, 0x0A CLUT4 ...),
       b10 palette present, b16-22 0x20, b24-31 0xAA (signature)
  +04  palette address (256 x 32-bit entries)
  +08  x start | x end << 16  (11 bits each)
  +0C  y start | y end << 16
  +14  b0-7 global alpha, b8-11 palette alpha level, b16-29 pitch in bytes
  +18  next head (physical; the chain ends at a head pointing to itself / 0)
  +1C  bitmap address (physical)
The GE (ge_m36f.py) draws the bitmaps; this module only reads them.
"""
import struct

import numpy as np

import ge_m36f

LAYER_REGS = (0x6300, 0x6380)       # (enable, base address) register pairs of GMA layers 0 / 1 (offsets in 0xB8000000)
PHYS = 0x07FFFFFF


def _w(ram, a, o=0):
    a = (a + o) & PHYS
    return int(ram[a:a + 4].view('<u4')[0]) if a + 4 <= ram.size else 0


def parse_head(ram, addr):
    w = [_w(ram, addr, 4 * i) for i in range(10)]
    h = {
        'addr': addr,
        'words': w,
        'enable': w[0] & 1,
        'format': (w[0] >> 4) & 0xF,
        'has_palette': (w[0] >> 10) & 1,
        'signature': w[0] >> 24,
        'palette': w[1] & 0x0FFFFFFF,
        'x0': w[2] & 0x7FF, 'x1': (w[2] >> 16) & 0x7FF,
        'y0': w[3] & 0x7FF, 'y1': (w[3] >> 16) & 0x7FF,
        'alpha': w[5] & 0xFF,
        'pal_alpha_level': (w[5] >> 8) & 0xF,
        'pitch': (w[5] >> 16) & 0x3FFF,
        'next': w[6] & 0x0FFFFFFF,
        'bitmap': w[7] & 0x0FFFFFFF,
    }
    return h


def layer_heads(ram, dev, layer=0, limit=64):
    """Heads of a GMA layer (list of dicts) and whether the layer is enabled."""
    en_off, base_off = LAYER_REGS[layer], LAYER_REGS[layer] + 4
    enabled = struct.unpack_from('<I', dev, en_off)[0] & 1
    a = struct.unpack_from('<I', dev, base_off)[0] & 0x0FFFFFFF
    heads, seen = [], set()
    while a and a not in seen and len(heads) < limit and a + 0x28 <= ram.size:
        seen.add(a)
        h = parse_head(ram, a)
        if h['signature'] != 0xAA:
            break
        heads.append(h)
        a = h['next']
    return enabled, heads


def _palette(ram, h):
    n = 256
    raw = ram[h['palette']:h['palette'] + 4 * n].view('<u4').astype(np.uint32)
    a = (raw >> 24).astype(np.float32)
    lvl = h['pal_alpha_level']
    amax = a.max() if a.size else 255
    if amax <= 15:
        a = a * 17.0
    elif amax <= 127:
        a = np.minimum(a * 2.0, 255.0)
    pal = np.stack([a, ((raw >> 16) & 255).astype(np.float32), ((raw >> 8) & 255).astype(np.float32),
                    (raw & 255).astype(np.float32)], -1)
    return pal, lvl


def render_head(ram, h):
    """(rgba uint8 (h, w, 4), x, y) of one region."""
    fmt = h['format']
    bpp = ge_m36f.BPP.get(fmt, 8)
    x0, x1, y0, y1 = h['x0'], h['x1'], h['y0'], h['y1']
    width = max(1, x1 - x0 + 1) if x1 >= x0 else max(1, h['pitch'] * 8 // bpp)
    height = max(1, y1 - y0 + 1) if y1 >= y0 else 1
    pitch_px = h['pitch'] * 8 // bpp if h['pitch'] else width
    width = min(width, pitch_px)
    g = ge_m36f.GeM36F(ram)
    pfreg = (fmt << 12) | (pitch_px & 0xFFF)
    raw = g._read_raw(h['bitmap'], pfreg, 0, 0, width, height)
    if fmt in ge_m36f.CLUT_FORMATS:
        pal, _ = _palette(ram, h)
        px = g._decode(raw, fmt, pfreg, pal)
    else:
        px = g._decode(raw, fmt, pfreg)
    ga = h['alpha']
    if ga <= 0x0F:                      # 4-bit global alpha (the driver sets 0x0F = opaque)
        ga *= 17
    if ga != 0xFF:
        px[..., 0] *= ga / 255.0
    rgba = np.clip(px[..., [1, 2, 3, 0]] + 0.5, 0, 255).astype(np.uint8)
    return rgba, x0, y0


def capture(ram, dev, screen=(1280, 720), background=(0, 0, 0)):
    """Composite all enabled regions of GMA layers 0 and 1 over a solid
    background (the video plane).  Returns (rgb uint8 (H, W, 3), info dict)."""
    W, H = screen
    canvas = np.empty((H, W, 3), np.float32)
    canvas[...] = background
    info = {'layers': []}
    for layer in range(len(LAYER_REGS)):
        enabled, heads = layer_heads(ram, dev, layer)
        info['layers'].append({'enabled': enabled, 'heads': heads})
        if not enabled:
            continue
        for h in heads:
            if not h['enable'] or not h['bitmap']:
                continue
            rgba, x, y = render_head(ram, h)
            hh, ww = rgba.shape[:2]
            hh, ww = min(hh, H - y), min(ww, W - x)
            if hh <= 0 or ww <= 0:
                continue
            src = rgba[:hh, :ww].astype(np.float32)
            a = src[..., 3:4] / 255.0
            canvas[y:y + hh, x:x + ww] = src[..., :3] * a + canvas[y:y + hh, x:x + ww] * (1 - a)
    return np.clip(canvas + 0.5, 0, 255).astype(np.uint8), info


def save_png(path, rgb):
    import os
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    try:
        from PIL import Image
        Image.fromarray(rgb).save(path)
        return
    except ImportError:
        pass
    import zlib
    h, w = rgb.shape[:2]
    raw = b"".join(b"\x00" + rgb[y].tobytes() for y in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
                chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
