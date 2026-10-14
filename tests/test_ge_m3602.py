#!/usr/bin/env python3
"""
The M3602's graphics engine (ge_m3602.py) and display layers
(gma_capture.m3602_layers), without firmware: commands laid out the way the
SDK's ge_hal_blt builds them are started through the engine's registers --
a fill and a copy in CLUT8, a scaled copy of a CLUT8 bitmap through its
palette into AYCbCr8888 inside a clip rectangle, and a command chained to
another -- and a layer head shows an AYCbCr8888 bitmap in a PAL output.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import numpy as np

import gma_capture
from ge_m3602 import GeM3602

failures = 0


def check(ok, text):
    global failures
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")


class Sim:
    """What GeM3602 uses of the simulator: RAM, the device window's registers and their store handlers."""
    def __init__(self):
        self.ram_size = 0x100000
        self.ram_buffer = bytearray(self.ram_size)
        self.dev = bytearray(0x10000)
        self.handlers = {}
        self.ge_ops = 0
        self.ge_render = True

    def _mmio_on(self, kind, handler, begin, end):
        self.handlers[begin] = handler

    def peek(self, address, n):
        return bytes(self.dev[address - 0xB8000000:address - 0xB8000000 + n])

    def poke(self, address, data):
        self.dev[address - 0xB8000000:address - 0xB8000000 + len(data)] = data

    def _dev_replay_of(self, uc, kind, address, data=None):
        return None                         # (no asynchronous stops here)

    def _dev_note(self, uc, kind, address, data):
        pass

    def store(self, offset, value):
        """A word store to the engine's register at offset, as the CPU's lands."""
        landed = self.handlers[0xC000 + offset](None, None, 0xB800C000 + offset, 4, value, None) \
            if 0xC000 + offset in self.handlers else None
        self.poke(0xB800C000 + offset, struct.pack("<I", value if landed is None else landed))


def put(sim, address, *words):
    struct.pack_into(f"<{len(words)}I", sim.ram_buffer, address, *words)


def command(sim, address, control, dst, src2, size, link=0, resize=None, clut=None, clip=None):
    """A command at address; returns its section mask.  dst = (address, x, y, pitch, format),
    src2 = (address, x, y, pitch, format, (w, h), colour), size = (w, h) of the destination rectangle."""
    a, x, y, pitch, fmt = dst
    words = [link, control, a, 0, x | y << 16, pitch | fmt << 16, 0, 0]
    mask = 0x23
    words += [0, 0, 0, 0, (size[0] - 1) | (size[1] - 1) << 16, 0]                      # source 1: the rectangle
    s, sx, sy, spitch, sfmt, (sw, sh), colour = src2
    words += [s, 0, sx | sy << 16, spitch | sfmt << 16, (sw - 1) | (sh - 1) << 16, colour]
    if resize:
        words += [0xCC00, resize[0] | resize[1] << 16, 0, 0]
        mask |= 0x08
    if clut is not None:
        words += [1 << 18, clut]
        mask |= 0x04
    if clip:
        words += [clip[0] | clip[1] << 16 | 1 << 31, clip[2] | clip[3] << 16]
        mask |= 0x40
    words += [0, 0, 0]                                                                   # colour key / blending
    put(sim, address, *words)
    return mask


def start(sim, address, mask):
    sim.store(0x0C, address >> 24 & 0xF)
    sim.store(0x10, mask << 24 | address & 0xFFFFFF)
    sim.store(0x00, 0x10)
    sim.store(0x00, 2)
    sim.store(0x00, 0)


def ram(sim, address, n):
    return bytes(sim.ram_buffer[address:address + n])


print("=== Test: the M3602's graphics engine (ge_m3602) ===")
sim = Sim()
ge = GeM3602(sim)
CLUT8, AYCBCR = 0x0B, 0x15

# a fill: 4 x 3 at (2, 1) of a CLUT8 bitmap with pitch 16, colour index 0x5A
m = command(sim, 0x1000, 0x00018010, (0x10000, 2, 1, 16, CLUT8), (0, 0, 0, 0, CLUT8, (1, 1), 0x5A5A5A5A), (4, 3))
start(sim, 0x1000, m)
rows = [ram(sim, 0x10000 + 16 * r, 8) for r in range(5)]
check(rows == [bytes(8)] + [b"\0\0" + b"\x5A" * 4 + b"\0\0"] * 3 + [bytes(8)],
      f"a fill writes the colour into the rectangle only ({[r.hex() for r in rows]})")
status = struct.unpack_from("<I", sim.dev, 0xC008)[0]
check(status & 2 and sim.ge_ops == 1 and struct.unpack_from("<I", sim.dev, 0xC004)[0] == 0,
      f"the start sets status bit 1, the engine reads idle, one GE command counted (status 0x{status:X})")
sim.store(0x08, 2)
check(struct.unpack_from("<I", sim.dev, 0xC008)[0] & 2 == 0, "writing 1 to the status bit clears it")

# a copy: 3 x 2 from (1, 0) of a CLUT8 bitmap into (0, 0) of another
sim.ram_buffer[0x20000:0x20010] = bytes(range(0x10, 0x20))
sim.ram_buffer[0x20010:0x20020] = bytes(range(0x20, 0x30))
m = command(sim, 0x1100, 0x00018008, (0x21000, 0, 0, 8, CLUT8), (0x20000, 1, 0, 16, CLUT8, (3, 2), 0), (3, 2))
start(sim, 0x1100, m)
check(ram(sim, 0x21000, 3) == bytes([0x11, 0x12, 0x13]) and ram(sim, 0x21008, 3) == bytes([0x21, 0x22, 0x23]),
      f"a copy moves the source rectangle ({ram(sim, 0x21000, 3).hex()} / {ram(sim, 0x21008, 3).hex()})")

# a scaled copy through the palette: CLUT8 4 x 4 -> AYCbCr8888 2 x 2 (steps of 2 source pixels), clipped to x >= 1
for i in range(256):
    put(sim, 0x30000 + 4 * i, 0x7F000000 | i * 0x010101)
sim.ram_buffer[0x22000:0x22010] = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
m = command(sim, 0x1200, 0x000182C8, (0x23000, 0, 0, 8, AYCBCR), (0x22000, 0, 0, 4, CLUT8, (4, 4), 0), (2, 2),
            resize=(2 * 8192, 2 * 8192), clut=0x30000, clip=(1, 0, 0x7FFF, 0x7FFF))
start(sim, 0x1200, m)
out = struct.unpack_from("<4I", sim.ram_buffer, 0x23000)
check(out == (0, 0x7F030303, 0, 0x7F0B0B0B),
      "the scaled copy takes every second pixel of every second row through the palette, inside the clip "
      f"rectangle ({' '.join(f'{v:08X}' for v in out)})")

# a chain: the first command's link word starts the second
m2 = command(sim, 0x1400, 0x00018010, (0x24000, 1, 0, 4, CLUT8), (0, 0, 0, 0, CLUT8, (1, 1), 0x22), (1, 1))
m1 = command(sim, 0x1300, 0x00018010, (0x24000, 0, 0, 4, CLUT8), (0, 0, 0, 0, CLUT8, (1, 1), 0x11), (1, 1),
             link=m2 << 24 | 0x1400)
start(sim, 0x1300, m1)
check(ram(sim, 0x24000, 2) == b"\x11\x22" and ge.commands == 5,
      f"a chained command runs after the first ({ram(sim, 0x24000, 2).hex()}, {ge.commands} commands run)")
check(ge.unsupported == {}, f"nothing unsupported ({ge.unsupported})")

print("=== Test: the M3602's display layers (gma_capture) ===")
mem = np.zeros(0x100000, np.uint8)
struct.pack_into("<8I", mem, 0x40000, 0, 0x41000, 10 | 2 << 13 | 11 << 17, 20 | 20 << 12 | 0x7F << 23, 1, 8, 0, 0)
struct.pack_into("<2I", mem, 0x41000, 0x7F80EB80, 0x7F801080)          # (Cb, Y, Cr, alpha): white, black
dev = bytearray(0x10000)
struct.pack_into("<I", dev, 0x61A0, 0x100)                            # layer 1 on
struct.pack_into("<I", dev, 0x61AC, 0x40000)
struct.pack_into("<I", dev, 0x600C, 625 << 16)                       # PAL
layers = gma_capture.m3602_layers(mem, bytes(dev))
check(len(layers) == 1 and (layers[0]['bitmap'], layers[0]['x0'], layers[0]['x1'], layers[0]['y0'], layers[0]['y1'],
                            layers[0]['format'], layers[0]['pitch']) == (0x41000, 10, 11, 20, 20, 2, 8),
      f"layer 1's head: AYCbCr8888, 2 x 1 at (10, 20) ({layers})")
rgb, info = gma_capture.capture(mem, bytes(dev))
fx, fy = 1280 / 720, 720 / 576
x0, y0 = round(10 * fx), round(20 * fy)
white, black = tuple(int(c) for c in rgb[y0, x0]), tuple(int(c) for c in rgb[y0, x0 + 2])
check(white == (255, 255, 255) and black == (0, 0, 0) and int(rgb.sum()) == 255 * 3 * 2 * 1,
      f"the capture scales the PAL layer to 1280 x 720: white at ({x0}, {y0}), then black ({white}, {black}, "
      f"{int(rgb.sum()) // 765} white pixels)")
struct.pack_into("<I", dev, 0x61A0, 0x1)
check(gma_capture.m3602_layers(mem, bytes(dev)) == [], "with layer 1 off nothing is shown")

print(f"\n[{'PASS' if not failures else 'FAIL'}] the M3602's graphics engine and display layers")
sys.exit(1 if failures else 0)
