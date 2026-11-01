#!/usr/bin/env python3
"""
The newer display engine's layers (gma_capture.de_registers / de_layers),
without firmware: a register list in RAM, handed to the display engine at
0xB8006080 with its load-enable bit, sets layer 0xB8006900 -- ARGB1555, a
2 x 2 bitmap at (16, 8) -- and a second list chained after it moves the
layer; the capture shows the bitmap's pixels there (a transparent one shows
the black behind it).  A list whose load-enable bit is clear sets nothing.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import numpy as np

import gma_capture

failures = 0


def check(ok, text):
    global failures
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")


def put(ram, address, *words):
    struct.pack_into(f"<{len(words)}I", ram, address, *words)


def register_list(ram, address, next_list, pairs):
    """A register list: the 0x20-byte header (+4 next, +8 count), then (register, value) pairs."""
    put(ram, address, 0, next_list, len(pairs), 0xC0)
    for i, (reg, value) in enumerate(pairs):
        put(ram, address + 0x20 + 8 * i, 0x18000000 | reg, value)


print("=== Test: the display engine's register lists and layers (gma_capture) ===")
ram = np.zeros(0x200000, np.uint8)
register_list(ram, 0x100000, 0x100200, [
    (0x6900, 0xF0100406),               # control: GE_PF_ARGB1555
    (0x6910, 0x04FF0000), (0x6914, 0x02CF0000),
    (0x6918, 2 << 16), (0x691C, 2 << 16), (0x6934, 2),
    (0x69A4, 1), (0x69E0, 0x101000)])
register_list(ram, 0x100200, 0, [(0x6910, 0x04FF0010), (0x6914, 0x02CF0008)])     # moved to (16, 8)
put(ram, 0x101000, 0, 0x102000)                                                    # the head: +4 the bitmap
struct.pack_into("<4H", ram, 0x102000, 0xFC00, 0x83E0, 0x801F, 0x0000)             # red, green / blue, transparent
dev = bytearray(0x10000)
put(dev, 0x6080, 0x100000, 1)

regs = gma_capture.de_registers(ram, bytes(dev))
check(regs.get(0x6900) == 0xF0100406 and regs.get(0x69E0) == 0x101000 and regs.get(0x6910) == 0x04FF0010,
      "the lists' registers, the chained list's value winning (0x6910 = 0x%08X)" % regs.get(0x6910, 0))
layers = gma_capture.de_layers(ram, bytes(dev))
layer = layers[0] if layers else {}
check(len(layers) == 1 and layer['enabled'] and layer['format'] == 0x05 and layer['bitmap'] == 0x102000
      and (layer['width'], layer['height'], layer['pitch'], layer['x'], layer['y']) == (2, 2, 2, 16, 8),
      f"layer 0x6900: on, ARGB1555 (GE code 0x05), 2 x 2 at (16, 8) from 0x102000 ({layer})")
rgb, info = gma_capture.capture(ram, bytes(dev))
pixels = [tuple(int(c) for c in rgb[y, x]) for y, x in ((8, 16), (8, 17), (9, 16), (9, 17))]
check(pixels == [(255, 0, 0), (0, 255, 0), (0, 0, 255), (0, 0, 0)],
      f"the capture shows red, green, blue and (transparent) black there ({pixels})")
check(int(rgb.sum()) == 3 * 255, "and nothing else")

put(dev, 0x6084, 0)
check(gma_capture.de_registers(ram, bytes(dev)) == {} and gma_capture.de_layers(ram, bytes(dev)) == [],
      "a list without its load-enable bit sets nothing")

# M3329E OSD_S36 / M3327 regions above 8 MB: raw_head in segment 0x00800000
# keeps seg_base = 0x00800000 for bitmap addresses and stops on w1 bit 20 (0x100000)
ram_m3329e = np.zeros(0x01000000, np.uint8)
dev_m3329e = bytearray(0x10000)
put(dev_m3329e, gma_capture.M3327_LAYER_ON, 1)
put(dev_m3329e, 0x41A4, 0x00AAEAB0)
# w0: 8 bpp (mode 2 << 2 = 8), next=0x2BEAC0 (ignored because w1 has 0x100000 end-of-chain)
# w1: bitmap offset 0x03000 (<< 4 = 0x030000 -> 0x00830000), end bit 0x100000, x1=15
put(ram_m3329e, 0x00AAEAB0, 0x002BEAC8, (15 << 22) | 0x100000 | 0x03000, 0, 7)
regs_m3329e = gma_capture.m3327_regions(ram_m3329e, bytes(dev_m3329e))
check(len(regs_m3329e) == 1 and regs_m3329e[0][1]['header'] == 0x00AAEAB0
      and regs_m3329e[0][1]['bitmap'] == 0x00830000 and regs_m3329e[0][1]['bpp'] == 8,
      f"m3327_regions preserves >8 MB segment base and w1 bit-20 chain end ({regs_m3329e})")

# C3505 G1 layer at 0xB8006A00 driven through 8-byte DMA channel 0x6088 in FXDE CLUT8 (0x0D -> GE 0x0C)
# with 256-entry ARGB8888 palette at 0x6AEC, resampled from 1920 x 1080 onto 1280 x 720
ram_g1 = np.zeros(0x400000, np.uint8)
dev_g1 = bytearray(0x10000)
register_list(ram_g1, 0x010000, 0, [
    (0x6A00, 0xF010000D),               # FXDE CLUT8 (0x0D -> GE 0x0C)
    (0x6A10, 0x077F0000), (0x6A14, 0x04370000),
    (0x6A18, 1920 << 16), (0x6A1C, 1080 << 16), (0x6A34, 1920),
    (0x6AA4, 1), (0x6AE0, 0x020000), (0x6AEC, 0x030000)])
put(ram_g1, 0x020000, 0, 0x100000)      # G1 head -> bitmap at 0x100000
put(ram_g1, 0x030000 + 4 * 7, 0xFFE70919)   # palette[7] = opaque crimson (0xE7, 0x09, 0x19)
bmp_g1 = ram_g1[0x100000:0x100000 + 1920 * 1080].reshape(1080, 1920)
bmp_g1[450:630, 600:1320] = 7           # centered 720 x 180 box -> resampled to (400..880, 300..420)
put(dev_g1, 0x6088, 0x010000, 1)
layers_g1 = gma_capture.de_layers(ram_g1, bytes(dev_g1))
check(len(layers_g1) == 1 and layers_g1[0]['base'] == 0x6A00 and layers_g1[0]['enabled']
      and layers_g1[0]['format'] == 0x0C and layers_g1[0]['palette'] == 0x030000,
      f"channel 0x6088 configures G1 layer 0x6A00 CLUT8 with palette at 0x6AEC ({layers_g1})")
rgb_g1, _ = gma_capture.capture(ram_g1, bytes(dev_g1))
center_px = tuple(int(c) for c in rgb_g1[360, 640])
corner_px = tuple(int(c) for c in rgb_g1[10, 10])
check(center_px == (0xE7, 0x09, 0x19) and corner_px == (0, 0, 0),
      f"1920 x 1080 CLUT8 G1 layer resampled to 1280 x 720 (center={center_px}, corner={corner_px})")

# M3327 direct-framebuffer OSD_M3327 mode (BigSat DSR 6500 Lux): 0x41A8 holds
# (pitch_bytes << 16) | height, 0x41A4 points directly to the 8 bpp framebuffer
ram_m3327d = np.zeros(0x100000, np.uint8)
dev_m3327d = bytearray(0x10000)
put(dev_m3327d, gma_capture.M3327_LAYER_ON, 0x0000800F)
put(dev_m3327d, 0x41A4, 0x80040000)
put(dev_m3327d, 0x41A8, (16 << 16) | 8)
put(dev_m3327d, 0x41B0, (0 << 10) | 15)
put(dev_m3327d, 0x41B4, (0 << 10) | 7)
ram_m3327d[0x040000:0x040000 + 16 * 8] = 3
regs_m3327d = gma_capture.m3327_regions(ram_m3327d, bytes(dev_m3327d))
check(len(regs_m3327d) == 1 and regs_m3327d[0][1]['header'] is None
      and regs_m3327d[0][1]['bitmap'] == 0x040000 and regs_m3327d[0][1]['bpp'] == 8
      and (regs_m3327d[0][1]['width'], regs_m3327d[0][1]['height'], regs_m3327d[0][1]['pitch']) == (16, 8, 16),
      f"m3327_regions decodes OSD_M3327 direct-framebuffer window ({regs_m3327d})")
rgba_m3327d = gma_capture.render_m3327(ram_m3327d, regs_m3327d[0][1], {3: (235 << 16) | (128 | 3) << 8 | (128 | 3)})
check(rgba_m3327d is not None and rgba_m3327d.shape == (8, 16, 4) and int(rgba_m3327d[0, 0, 3]) == 255,
      f"render_m3327 renders OSD_M3327 direct-framebuffer pixels ({None if rgba_m3327d is None else rgba_m3327d[0, 0].tolist()})")

# 74HC164 shift-register multiplexed 4-digit front panel (PAN_COMMON_0, hc164_decoder.py)
from hc164_decoder import HC164Decoder
hc = HC164Decoder(clk_gpio=16, data_gpio=17, digit_gpios=(18, 19, 20, 21))
def hc_shift(sr_byte, strobe_idx):
    all_hi = (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21)
    for i in range(7, -1, -1):
        d = ((sr_byte >> i) & 1) << 17
        hc.on_gpio_write(0xB8000054, 4, all_hi | d)
        hc.on_gpio_write(0xB8000054, 4, all_hi | d | (1 << 16))
    hc.on_gpio_write(0xB8000054, 4, (all_hi ^ (1 << (18 + strobe_idx))) | (1 << 16))
    hc.on_gpio_write(0xB8000054, 4, all_hi | (1 << 16))
for idx, raw_b in enumerate((0xFF, 0xC0, 0xC8, 0xFF)):
    hc_shift(0x00, idx) if False else None
    hc_shift(raw_b, idx)
check(hc.get_display_text() == " ON ", f"HC164Decoder decodes ' ON ' -> {hc.get_display_text()!r}")
for idx in range(4):
    hc_shift(0xBF, idx)
check(hc.get_display_text() == "----", f"HC164Decoder decodes '----' -> {hc.get_display_text()!r}")

print(f"\n[{'PASS' if not failures else 'FAIL'}] display engine register lists and layers")
sys.exit(1 if failures else 0)
