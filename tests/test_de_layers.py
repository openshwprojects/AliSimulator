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

print(f"\n[{'PASS' if not failures else 'FAIL'}] display engine register lists and layers")
sys.exit(1 if failures else 0)
