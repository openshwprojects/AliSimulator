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

The M3602's display layers (the SDK's ge_m36.c / ge_lld.c, which the
Ferguson T50 runs) are older: 0xB80061A0 holds layer 0's enable in bit 0
and layer 1's in bit 8, 0xB80061A8 / 0xB80061AC the address of each one's
head, which ge_hal_m36_set_gma fills in:
  +04  bitmap address
  +08  x start (bits 0..10) | pixel format (bits 13..16: 2 AYCbCr8888,
       0xD / 0xE CLUT8, gma_pixel_fmt_convt) | x end (bits 17..27)
  +0C  y start (bits 0..10) | y end (bits 12..22) | alpha (bits 23..30)
  +14  pitch in bytes
  +18  the palette's address (32-byte aligned)
A pixel or palette entry is Cb, Y, Cr and a 7-bit alpha.  The coordinates
are the output's: the T50's OSD driver has the GE scale its 912 x 640 CLUT8
screen to the TV system's size itself (513 x 512 for PAL, at 103, 32), so
the capture scales the layer up to its 1280 x 720 canvas (output_scale).

The M3329's OSD (OSD_M3327C, chips/m3329.py) has two layers, enabled by
bits 0 and 16 of 0xB80041A0, whose registers at 0xB80041A4 / 0xB80041C4 hold
the address of the first of a chain of 16-byte region headers in RAM
(m3327_regions); a region is a 2, 4 or 8 bpp bitmap through its layer's
256-entry palette, which the driver writes through a port (0xB80041AC /
0xB80041C8) and the simulator records, a 4 bpp region using one bank of 16.
The application's PAL output (0xB800400C) is scaled to the canvas.

The newer display engine of the Ferguson T750i (an M3821 with the SDK's
dual-CPU build) has layers of its own at 0xB8006900 and 0xB8006B00, which
no CPU store sets: the drivers build register lists in RAM and hand them to
the display engine (DE_LIST_CHANNELS: the list's physical address, then a
load-enable bit at +4), which loads them every frame.  A list is a 0x20-byte
header (+4 the next list, +8 the number of pairs) and that many (register's
physical address, value) pairs.  A layer (DE_LAYERS) then has its control
word at +0 (b0-4 the pixel format, the SDK's GE_PIXEL_FORMAT), its bitmap's
size at +18 / +1C (in the upper halves), its pitch in pixels at +34, an
enable bit at +A4 and at +E0 a head in RAM whose second word is the bitmap
address.  de_registers() and de_layers() read that the way the hardware
does, at the moment of the capture.
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
    ga = h['alpha']
    if ga <= 0x0F:                      # 4-bit global alpha (the driver sets 0x0F = opaque)
        ga *= 17
    if fmt in ge_m36f.CLUT_FORMATS:
        pal, _ = _palette(ram, h)
        if fmt not in (0x0E, 0x0B):
            if ga != 0xFF:
                pal[:, 0] *= ga / 255.0
            pal_rgba = np.clip(pal[:, [1, 2, 3, 0]] + 0.5, 0, 255).astype(np.uint8)
            if raw.dtype == np.uint8 and pal_rgba.shape[0] >= 256:
                return pal_rgba[raw], x0, y0
            return pal_rgba[np.minimum(raw, pal_rgba.shape[0] - 1)], x0, y0
        px = g._decode(raw, fmt, pfreg, pal)
        if ga != 0xFF:
            px[..., 0] *= ga / 255.0
        rgba = np.clip(px[..., [1, 2, 3, 0]] + 0.5, 0, 255).astype(np.uint8)
    else:
        rgba = g.decode_rgba_u8(raw, fmt, pfreg, ga)
    return rgba, x0, y0


M3602_LAYER_ON = 0x61A0
M3602_HEADS = ((0x61A8, 0x001), (0x61AC, 0x100))        # (head address register, its bit in M3602_LAYER_ON)


def m3602_layers(ram, dev):
    """The M3602's enabled display layers: dicts with the head's fields."""
    on = struct.unpack_from('<I', dev, M3602_LAYER_ON)[0]
    layers = []
    for reg, bit in M3602_HEADS:
        a = struct.unpack_from('<I', dev, reg)[0] & PHYS
        if not on & bit or not a:
            continue
        w = [_w(ram, a, 4 * i) for i in range(8)]
        layers.append({
            'head': a, 'words': w,
            'bitmap': w[1] & PHYS,
            'x0': w[2] & 0x7FF, 'x1': (w[2] >> 17) & 0x7FF, 'format': (w[2] >> 13) & 0xF,
            'y0': w[3] & 0x7FF, 'y1': (w[3] >> 12) & 0x7FF, 'alpha': (w[3] >> 23) & 0xFF,
            'pitch': w[5] & 0xFFFF,
            'palette': w[6] & 0x07FFFFE0,
        })
    return layers


def render_m3602(ram, layer):
    """rgba uint8 (h, w, 4) of an M3602 layer's bitmap; None for a format not modelled."""
    width, height = layer['x1'] - layer['x0'] + 1, layer['y1'] - layer['y0'] + 1
    pitch, fmt, a = layer['pitch'], layer['format'], layer['bitmap']
    bpp = 4 if fmt == 2 else 1 if fmt in (0xD, 0xE) else 0
    if not bpp or width <= 0 or height <= 0 or pitch < width * bpp or a + height * pitch > ram.size:
        return None
    rows = ram[a:a + height * pitch].reshape(height, pitch)[:, :width * bpp]
    if bpp == 4:
        px = rows.reshape(height, width, 4)
    else:
        pal = layer['palette']
        if pal + 1024 > ram.size:
            return None
        px = ram[pal:pal + 1024].reshape(256, 4)[rows]
    rgb = ge_m36f.GeM36F._ycbcr_to_rgb(px[..., [1, 0, 2]].astype(np.float32), 0)
    alpha = np.minimum(px[..., 3].astype(np.float32) * (255.0 / 127.0), 255.0)
    return np.clip(np.concatenate([rgb, alpha[..., None]], -1) + 0.5, 0, 255).astype(np.uint8)


M3327_LAYER_ON = 0x41A0
M3327_HEADS = ((0x41A4, 0x00001), (0x41C4, 0x10000))    # (first header register, its bit in M3327_LAYER_ON)
M3327_TIMING_REG = 0x400C           # b16-26 the video output's total lines, as DE_TIMING_REG
M3327_BPP = {0: 2, 1: 4, 2: 8, 3: 4}


def m3327_regions(ram, dev):
    """The M3329's OSD regions (OSD_M3327C): [(layer, region dict)] of the
    enabled layers, each layer's chain of 16-byte headers in RAM from its
    register:
      +0  b2-3 colour mode (0 2 bpp, 1 4 bpp, 2 8 bpp, 3 4 bpp), b4-22 the
          next header (0 ends), b24-27 the palette bank of a 2 / 4 bpp region
      +4  b0-18 the bitmap address >> 4, b22-31 x end
      +8  b0-9 the height, b22-31 x start
      +C  b0-9 y end, b16-25 y start
    a bitmap's rows being the width's bytes rounded up to 16."""
    on = struct.unpack_from('<I', dev, M3327_LAYER_ON)[0]
    regions = []
    for layer, (reg, bit) in enumerate(M3327_HEADS):
        a = struct.unpack_from('<I', dev, reg)[0] & 0x7FFFF0
        seen = set()
        while on & bit and a and a not in seen and len(seen) < 64:
            seen.add(a)
            w0, w1, w2, w3 = (_w(ram, a, 4 * i) for i in range(4))
            bpp = M3327_BPP[(w0 >> 2) & 3]
            x0, x1, y0, y1 = w2 >> 22, w1 >> 22, (w3 >> 16) & 0x3FF, w3 & 0x3FF
            width = x1 - x0 + 1
            regions.append((layer, {
                'header': a, 'words': (w0, w1, w2, w3), 'bpp': bpp, 'bank': (w0 >> 24) & 0xF,
                'x0': x0, 'y0': y0, 'width': width, 'height': y1 - y0 + 1,
                'bitmap': (w1 & 0x7FFFF) << 4, 'pitch': (width * bpp // 8 + 15) & ~15,
            }))
            a = w0 & 0x7FFFF0
    return regions


def render_m3327(ram, region, palette):
    """rgba uint8 (h, w, 4) of an M3327 OSD region through its layer's palette
    ({index: Y << 16 | Cb << 8 | Cr}, chips/m3329.Osd); None if it does not fit."""
    w, h, pitch, a = region['width'], region['height'], region['pitch'], region['bitmap']
    if w <= 0 or h <= 0 or w > 1024 or h > 1024 or a + h * pitch > ram.size:
        return None
    raw = ram[a:a + h * pitch].reshape(h, pitch)
    bpp = region['bpp']
    if bpp == 8:
        idx = raw[:, :w].astype(np.int32)
    else:
        shifts = range(8 - bpp, -1, -bpp)
        idx = np.stack([(raw >> s) & ((1 << bpp) - 1) for s in shifts], -1).reshape(h, -1)[:, :w].astype(np.int32)
        idx += region['bank'] << bpp
    lut = np.zeros((256, 4), np.float32)
    for i, v in palette.items():
        cb, cr = (v >> 8) & 0xFF, v & 0xFF
        lut[i & 0xFF] = (v >> 16, cb & 0xFC, cr & 0xFC, (((cb & 3) << 2) | (cr & 3)) * 17)
    px = lut[idx & 0xFF]
    rgb = ge_m36f.GeM36F._ycbcr_to_rgb(px[..., :3], 0)
    return np.clip(np.concatenate([rgb, px[..., 3:4]], -1) + 0.5, 0, 255).astype(np.uint8)


DE_LIST_CHANNELS = (0x6080, 0x6090, 0x60A0, 0x60B0)     # (list address, +4 load enable) of the register lists
DE_LAYERS = (0x6900, 0x6B00)
# the SDK's GE_PIXEL_FORMAT (ge.h) -> the GE's HW format codes ge_m36f decodes (no CLUT formats:
# where their palette is, is not known yet)
DE_FORMATS = {0x00: 0x06, 0x01: 0x00, 0x02: 0x04, 0x03: 0x02, 0x05: 0x01, 0x06: 0x05, 0x07: 0x03}


def de_registers(ram, dev):
    """{register offset: value} the display engine's enabled register lists
    set (a later list's value for a register wins)."""
    regs = {}
    for channel in DE_LIST_CHANNELS:
        head, enabled = struct.unpack_from('<II', dev, channel)
        seen = set()
        while enabled & 1 and head and head not in seen and len(seen) < 64:
            seen.add(head)
            _flags, nxt, count = (_w(ram, head, 4 * i) for i in range(3))
            if count > 512:
                break
            for i in range(count):
                reg = _w(ram, head, 0x20 + 8 * i)
                if reg >> 24 & 0x1F == 0x18:                    # (a register of the device window)
                    regs[reg & 0xFFFFFF] = _w(ram, head, 0x24 + 8 * i)
            head = nxt & PHYS
    return regs


def de_layers(ram, dev):
    """The display engine's layers the register lists configure: dicts with
    the layer's base, whether it is on, its bitmap (address, HW format,
    width, height, pitch in pixels) and where it starts on the screen
    (the low halves of +10 / +14)."""
    regs = de_registers(ram, dev)
    layers = []
    for base in DE_LAYERS:
        head = regs.get(base + 0xE0)
        if not head:
            continue
        fmt = DE_FORMATS.get(regs.get(base, 0) & 0x1F)
        layers.append({
            'base': base,
            'enabled': bool(regs.get(base + 0xA4, 0) & 1) and fmt is not None,
            'format': fmt,
            'bitmap': _w(ram, head, 4) & PHYS,
            'width': regs.get(base + 0x18, 0) >> 16,
            'height': regs.get(base + 0x1C, 0) >> 16,
            'pitch': regs.get(base + 0x34, 0) & 0xFFFF,
            'x': regs.get(base + 0x10, 0) & 0x7FF,
            'y': regs.get(base + 0x14, 0) & 0x7FF,
        })
    return layers


def render_de_layer(ram, layer):
    """rgba uint8 (h, w, 4) of a display-engine layer's bitmap."""
    fmt, width, height = layer['format'], layer['width'], layer['height']
    pitch = layer['pitch'] or width
    g = ge_m36f.GeM36F(ram)
    pfreg = (fmt << 12) | (pitch & 0xFFF)
    raw = g._read_raw(layer['bitmap'], pfreg, 0, 0, width, height)
    return g.decode_rgba_u8(raw, fmt, pfreg)


DE_TIMING_REG = 0x600C              # b16-26 total lines of the output TV mode (625 PAL, 525 NTSC, 750 720p, 1125 1080i)
OUTPUT_SIZE = {625: (720, 576), 525: (720, 480), 750: (1280, 720), 1125: (1920, 1080)}


def output_mode(dev):
    """(total lines, (width, height)) of the display engine's output TV mode,
    (0, None) when its timing register is not programmed."""
    lines = (struct.unpack_from('<I', dev, DE_TIMING_REG)[0] >> 16) & 0x7FF
    return lines, OUTPUT_SIZE.get(lines)


def output_scale(dev, screen=(1280, 720)):
    """(fx, fy): how much larger the OSD's own 1280 x 720 canvas is than the
    display engine's output frame.  A firmware driving another TV mode has
    the display engine scale its GMA layer to the output, and the region
    heads then hold OUTPUT coordinates: the Strong Prima VIII and SRT 8115
    drive PAL (720 x 576), the Prima's banner region being 77..643 x 32..543
    (567 x 512) for a 1008 x 640 bitmap; the Cabletechs drive 1080i (the
    URZ0083Q / URZ0194S switch to it when their wizard starts, the URZ0195's
    2012 firmware from the start), a 1008 x 640 bitmap shown 1.5x larger in a
    1512 x 960 window at (204, 60), centred in the 1920 x 1080 frame.  (1, 1)
    for 720p and when the timing register is not programmed."""
    lines, out = output_mode(dev)
    if not out:
        return 1.0, 1.0
    return screen[0] / out[0], screen[1] / out[1]


def _place_rgb_u8(rgb, x0, y0, screen, background):
    W, H = screen
    hh, ww = rgb.shape[:2]
    hh, ww = min(hh, H - y0), min(ww, W - x0)
    if x0 == 0 and y0 == 0 and hh == H and ww == W:
        return np.ascontiguousarray(rgb[:hh, :ww])
    out = np.empty((H, W, 3), np.uint8)
    out[...] = background
    if hh > 0 and ww > 0:
        out[y0:y0 + hh, x0:x0 + ww] = rgb[:hh, :ww]
    return out


def _render_head_on_bg(ram, h, screen, background):
    fmt = h['format']
    if fmt not in (0x08, 0x09, 0x0A, 0x0C) and fmt not in ge_m36f._PACKED16_FMTS:
        return None
    bpp = ge_m36f.BPP.get(fmt, 8)
    x0, x1, y0, y1 = h['x0'], h['x1'], h['y0'], h['y1']
    width = max(1, x1 - x0 + 1) if x1 >= x0 else max(1, h['pitch'] * 8 // bpp)
    height = max(1, y1 - y0 + 1) if y1 >= y0 else 1
    pitch_px = h['pitch'] * 8 // bpp if h['pitch'] else width
    width = min(width, pitch_px)
    W, H = screen
    hh, ww = min(height, H - y0), min(width, W - x0)
    if hh <= 0 or ww <= 0:
        out = np.empty((H, W, 3), np.uint8)
        out[...] = background
        return out
    g = ge_m36f.GeM36F(ram)
    pfreg = (fmt << 12) | (pitch_px & 0xFFF)
    raw = g._read_raw(h['bitmap'], pfreg, 0, 0, ww, hh)
    ga = h['alpha']
    if ga <= 0x0F:
        ga *= 17
    if fmt in (0x08, 0x09, 0x0A, 0x0C):
        pal, _ = _palette(ram, h)
        if ga != 0xFF:
            pal[:, 0] *= ga / 255.0
        pal_rgba = np.clip(pal[:, [1, 2, 3, 0]] + 0.5, 0, 255).astype(np.uint8)
        a = pal_rgba[:, 3:4].astype(np.float32) / 255.0
        bg_f = np.array(background, dtype=np.float32)
        rgb_f = pal_rgba[:, :3].astype(np.float32) * a + bg_f * (1.0 - a)
        lut_u8 = np.zeros((pal_rgba.shape[0], 4), np.uint8)
        lut_u8[:, :3] = np.clip(rgb_f + 0.5, 0, 255).astype(np.uint8)
        lut_u32 = lut_u8.view(np.uint32).reshape(-1)
        idx = raw if (raw.dtype == np.uint8 and lut_u32.shape[0] >= 256) else np.minimum(raw, lut_u32.shape[0] - 1)
        rgb = lut_u32[idx].view(np.uint8).reshape(hh, ww, 4)[..., :3]
        return _place_rgb_u8(rgb, x0, y0, screen, background)
    rgb = g.decode_rgb_on_bg_u8(raw, fmt, pfreg, ga, background)
    return _place_rgb_u8(rgb, x0, y0, screen, background) if rgb is not None else None


def _render_de_on_bg(ram, layer, screen, background):
    fmt, width, height = layer['format'], layer['width'], layer['height']
    if fmt not in ge_m36f._PACKED16_FMTS:
        return None
    x0, y0 = layer['x'], layer['y']
    W, H = screen
    hh, ww = min(height, H - y0), min(width, W - x0)
    if hh <= 0 or ww <= 0:
        out = np.empty((H, W, 3), np.uint8)
        out[...] = background
        return out
    pitch = layer['pitch'] or width
    g = ge_m36f.GeM36F(ram)
    pfreg = (fmt << 12) | (pitch & 0xFFF)
    raw = g._read_raw(layer['bitmap'], pfreg, 0, 0, ww, hh)
    rgb = g.decode_rgb_on_bg_u8(raw, fmt, pfreg, 0xFF, background)
    return _place_rgb_u8(rgb, x0, y0, screen, background) if rgb is not None else None


def capture(ram, dev, screen=(1280, 720), background=(0, 0, 0), m3327_palettes=None, video_rgb=None):
    """Composite all enabled regions of GMA layers 0 and 1 over a solid
    background (or over `video_rgb`, the video plane).  Returns (rgb uint8
    (H, W, 3), info dict).
    In an SD or 1080i output mode the regions are drawn at the size their
    bitmaps have, at the scaled-back position (the display engine's scaling
    undone, see output_scale), so the picture is what the TV shows, at the
    OSD's own resolution.  m3327_palettes: the M3329's OSD layers' palettes
    (chips/m3329.Osd) -- its regions are drawn too, scaled from its output
    frame to the canvas like the M3602's."""
    W, H = screen
    fx, fy = output_scale(dev, screen)
    info = {'layers': [], 'output_scale': (fx, fy)}
    active_heads = []
    for layer in range(len(LAYER_REGS)):
        enabled, heads = layer_heads(ram, dev, layer)
        info['layers'].append({'enabled': enabled, 'heads': heads})
        if not enabled:
            continue
        for h in heads:
            if not h['enable'] or not h['bitmap']:
                continue
            if (fx, fy) != (1.0, 1.0) and h['x1'] >= h['x0'] and h['y1'] >= h['y0']:
                # the window the output shows, scaled back to the bitmap's pixels --
                # only when the bitmap is wide enough for that (a layer the display
                # engine shows 1:1 is not scaled)
                vw = round((h['x1'] - h['x0'] + 1) * fx)
                vh = round((h['y1'] - h['y0'] + 1) * fy)
                pitch_px = h['pitch'] * 8 // ge_m36f.BPP.get(h['format'], 8) if h['pitch'] else 0
                if vw <= pitch_px + 16:
                    # (a window a few pixels wider than the bitmap is the firmware's own
                    # rounding of the scaled size: the SRT 8115's 568-px PAL window
                    # scales back to 1010 for its 1008-px bitmap, the Prima's 567 to 1008)
                    vw = min(vw, pitch_px)
                    h = dict(h, x0=round(h['x0'] * fx), y0=round(h['y0'] * fy))
                    h['x1'], h['y1'] = h['x0'] + vw - 1, h['y0'] + vh - 1
                    h['scaled_back'] = (fx, fy)
            active_heads.append(h)
    info['m3602_layers'] = m3602_layers(ram, dev)
    if m3327_palettes is not None:
        info['m3327_regions'] = m3327_regions(ram, dev)
    info['de_layers'] = de_layers(ram, dev)
    active_de = [layer for layer in info['de_layers']
                 if layer['enabled'] and layer['bitmap'] and layer['width'] and layer['height']]
    if video_rgb is None and not info['m3602_layers'] and not info.get('m3327_regions'):
        if not active_heads and not active_de:
            out = np.empty((H, W, 3), np.uint8)
            out[...] = background
            return out, info
        if len(active_heads) == 1 and not active_de:
            res = _render_head_on_bg(ram, active_heads[0], screen, background)
            if res is not None:
                return res, info
        elif len(active_de) == 1 and not active_heads:
            res = _render_de_on_bg(ram, active_de[0], screen, background)
            if res is not None:
                return res, info
    if video_rgb is not None:
        vh, vw = video_rgb.shape[:2]
        if (vw, vh) != (W, H):
            rows = np.minimum((np.arange(H) * vh // H).astype(int), vh - 1)
            cols = np.minimum((np.arange(W) * vw // W).astype(int), vw - 1)
            video_bg = video_rgb[rows][:, cols]
        else:
            video_bg = video_rgb
        if not info['m3602_layers'] and not info.get('m3327_regions') and not active_heads and not active_de:
            return video_bg.copy(), info
        canvas = video_bg.astype(np.float32)
    else:
        canvas = np.empty((H, W, 3), np.float32)
        canvas[...] = background
    for h in active_heads:
        rgba, x, y = render_head(ram, h)
        _blend(canvas, rgba, x, y)
    # the M3602's layers (the T50), in the output's coordinates: scaled up to the canvas
    for layer in info['m3602_layers']:
        rgba = render_m3602(ram, layer)
        if rgba is None:
            continue
        h, w = rgba.shape[:2]
        rows = np.minimum((np.arange(round(h * fy)) / fy).astype(int), h - 1)
        cols = np.minimum((np.arange(round(w * fx)) / fx).astype(int), w - 1)
        _blend(canvas, rgba[rows][:, cols], round(layer['x0'] * fx), round(layer['y0'] * fy))
    # the M3329's OSD layers, in its PAL output's coordinates: scaled up to the canvas
    if m3327_palettes is not None:
        lines = (struct.unpack_from('<I', dev, M3327_TIMING_REG)[0] >> 16) & 0x7FF
        out = OUTPUT_SIZE.get(lines, (720, 576))
        gx, gy = W / out[0], H / out[1]
        for layer, region in info['m3327_regions']:
            rgba = render_m3327(ram, region, m3327_palettes[layer])
            if rgba is None:
                continue
            h, w = rgba.shape[:2]
            rows = np.minimum((np.arange(round(h * gy)) / gy).astype(int), h - 1)
            cols = np.minimum((np.arange(round(w * gx)) / gx).astype(int), w - 1)
            _blend(canvas, rgba[rows][:, cols], round(region['x0'] * gx), round(region['y0'] * gy))
    # the newer display engine's layers (the T750i), on top
    for layer in active_de:
        _blend(canvas, render_de_layer(ram, layer), layer['x'], layer['y'])
    canvas += 0.5
    np.clip(canvas, 0, 255, out=canvas)
    return canvas.astype(np.uint8), info


def _blend(canvas, rgba, x, y):
    """Alpha-blend an RGBA image onto the canvas at (x, y), clipped to it."""
    H, W = canvas.shape[:2]
    hh, ww = rgba.shape[:2]
    hh, ww = min(hh, H - y), min(ww, W - x)
    if hh <= 0 or ww <= 0:
        return
    alpha_u8 = rgba[:hh, :ww, 3]
    if int(alpha_u8.max()) == 0:
        return
    dst = canvas[y:y + hh, x:x + ww]
    if int(alpha_u8.min()) == 255:
        dst[:] = rgba[:hh, :ww, :3]
        return
    a = alpha_u8[..., None].astype(np.float32)
    a /= 255.0
    src_rgb = rgba[:hh, :ww, :3].astype(np.float32)
    src_rgb *= a
    dst *= (1.0 - a)
    dst += src_rgb


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
