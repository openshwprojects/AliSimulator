#!/usr/bin/env python3
"""
The crypto engine's DMA and SHA unit (crypto_engine.py), without firmware: a
DMA job feeding the SHA unit hashes its source with SHA-256, the digest's
words read through the index register, the job's done bit interrupts on
line 44 while its enable is set and the acknowledge (write 1 to clear) drops
it; the SHA unit started on its own source and length (SHA-1) the same.
"""
import hashlib
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from crypto_engine import CE, CryptoEngine

failures = 0


def check(ok, text):
    global failures
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")


class Chip:
    see = None


class Sim:
    """What CryptoEngine uses of a core: RAM, the device registers and their store handlers, an interrupt controller."""
    def __init__(self):
        self.ram_size = 0x100000
        self.ram_buffer = bytearray(self.ram_size)
        self.dev = bytearray(0x100000)
        self.handlers = {}
        self.chip = Chip()
        self._ic = 0xB8000030
        self._ic_lines = 0
        self.raised = []

    def _mmio_on(self, kind, handler, begin, end):
        self.handlers[begin] = handler

    def peek(self, address, n):
        return bytes(self.dev[address - 0xB8000000:address - 0xB8000000 + n])

    def poke(self, address, data):
        self.dev[address - 0xB8000000:address - 0xB8000000 + len(data)] = data

    def _ic_set_line(self, line, on):
        self._ic_lines = (self._ic_lines | 1 << line) if on else (self._ic_lines & ~(1 << line))
        self.raised.append((line, on))

    def _dev_replay_of(self, uc, kind, address, data=None):
        return None                         # (no asynchronous stops here)

    def _dev_note(self, uc, kind, address, data):
        pass

    def store(self, offset, value):
        """A word store to the engine's register at offset, as the CPU's lands."""
        handler = self.handlers.get(CE + offset)
        uc = self

        class Uc:
            @staticmethod
            def mem_read(address, n):
                return uc.peek(address, n)
        landed = handler(Uc, None, 0xB8000000 + CE + offset, 4, value, None) if handler else None
        self.poke(0xB8000000 + CE + offset, struct.pack("<I", value if landed is None else landed))

    def load(self, offset):
        return struct.unpack_from("<I", self.dev, CE + offset)[0]


print("=== Test: the crypto engine's DMA and SHA unit (crypto_engine) ===")
sim = Sim()
ce = CryptoEngine(sim)
data = bytes(range(256)) * 512                     # 0x20000 bytes at 0x10000
sim.ram_buffer[0x10000:0x10000 + len(data)] = data
sim.poke(0xB800003C, struct.pack("<I", 1 << (44 - 32)))    # the controller enables line 44

sim.store(0x300, 0x40000000)                       # SHA-256
sim.store(0x318, 0x20)                             # the SHA unit takes the DMA's data
sim.store(0x80, 0x10000)
sim.store(0x88, len(data))
sim.store(0x90, 0x1000)                            # the done bit's interrupt enabled
sim.store(0x90, 0x51000)                           # start
want = struct.unpack(">8I", hashlib.sha256(data).digest())
words = []
for i in range(8):
    sim.store(0x318, 0x20 | i)
    words.append(sim.load(0x314))
check(tuple(words) == want, f"a DMA job hashes its source with SHA-256 ({words[0]:08X}..., want {want[0]:08X}...)")
check(sim.load(0x90) & (1 << 16) == 0 and sim.load(0x94) & 0x10 and sim.load(0x304) & 1,
      "the start bit clears itself, the DMA's done bit and the digest's ready bit are set")
check(sim._ic_lines >> 44 & 1, "the done bit interrupts on line 44 (enabled in the controller)")
sim.store(0x90, sim.load(0x90) & ~0x3300)          # the ISR turns the enables off
check(not sim._ic_lines >> 44 & 1, "the line drops with the enables off")
sim.store(0x94, 0x10)
sim.store(0x304, 1)
check(sim.load(0x94) & 0x10 == 0 and sim.load(0x304) & 1 == 0, "writing 1 clears the done and ready bits")

sim.store(0x300, 0x00000000)                       # SHA-1, on its own source and length
sim.ram_buffer[0x20000:0x20003] = b"abc"
sim.store(0x308, 0x20000)
sim.store(0x30C, 3)
sim.store(0x300, 0x00000001)
words = []
for i in range(5):
    sim.store(0x318, i)
    words.append(sim.load(0x314))
check(tuple(words) == struct.unpack(">5I", hashlib.sha1(b"abc").digest()) and sim.load(0x300) & 1 == 0,
      f"the SHA unit started on its own hashes its source and length (SHA-1 'abc': {words[0]:08X}...)")
check(ce.jobs == 2, f"two jobs ({ce.jobs})")

print(f"\n[{'PASS' if not failures else 'FAIL'}] the crypto engine's DMA and SHA unit")
sys.exit(1 if failures else 0)
