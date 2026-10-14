"""
The crypto engine of the S3602-platform dual-CPU chips at 0xB8034000 (its
random number generator, chips/see.py Trng, is its +0x400): the DMA that
feeds it and its SHA unit, as far as the M3503's SEE program uses them --
the Globo HD-XS2's application asks the SEE (HLD_DSC.16) to hash its own
code, 0xA0000200 up, with SHA-256 in jobs of 0x20000 bytes, and waited for
the answer for good: the SEE's driver started the DMA and waited for its
interrupt, which nothing raised.

  DMA   +0x80   source (physical)
        +0x88   length in bytes
        +0x90   control: bit 16 starts the job; bits 8..13 enable the
                status bits 0..5 as interrupts
        +0x94   status: bit 4 the job is done (write 1 to clear); bit 8 busy
  SHA   +0x300  bits 29..31 the algorithm (0 SHA-1, 1 SHA-224, 2 SHA-256,
                3 SHA-384, 4 SHA-512 -- the driver reads 5, 7, 8, 12, 16
                words); bit 0 starts it on +0x308 (source) / +0x30C (length)
        +0x304  bit 0 the digest is ready (write 1 to clear)
        +0x314  the digest's word the low nibble of +0x318 selects (word 0
                first, each a big-endian 32-bit word of the digest)
        +0x318  bit 5: the SHA unit takes the DMA's data

A job runs at once: the DMA's data (from the shared RAM) is hashed as one
message, the digest ready and the DMA's done bit set, which interrupts
(interrupt-controller line 44, OS IRQ 52) the cores whose controller enables
it -- the SEE's.
"""
import hashlib
import struct

CE = 0x34000                            # in the device window
CE_LINE = 44
ALGORITHMS = {0: "sha1", 1: "sha224", 2: "sha256", 3: "sha384", 4: "sha512"}
DMA_SRC, DMA_LEN, DMA_CTRL, DMA_STATUS = 0x80, 0x88, 0x90, 0x94
SHA_CTRL, SHA_STATUS, SHA_SRC, SHA_LEN, SHA_WORD, SHA_INDEX = 0x300, 0x304, 0x308, 0x30C, 0x314, 0x318
DMA_START, DMA_DONE = 1 << 16, 0x10
SHA_FROM_DMA = 0x20


def _merge(uc, address, size, value):
    """(the register word with this store applied, shift, mask of the stored bytes)."""
    shift = (address & 3) * 8
    mask = ((1 << (size * 8)) - 1) << shift
    word = int.from_bytes(uc.mem_read(address & ~3, 4), 'little')
    return (word & ~mask) | ((value << shift) & mask), shift, mask


class CryptoEngine:
    def __init__(self, sim):
        self.sim = sim
        self.digest = []                # the last digest's words
        self.jobs = 0
        self.wire(sim)

    def wire(self, core):
        """The registers' handlers on a core (the starts know their core: a store an asynchronous stop
        rewound runs its handler again, and must not start the job twice)."""
        core._mmio_on('w', lambda *a: self._write_dma_control(core, *a), CE + DMA_CTRL, CE + DMA_CTRL + 3)
        core._mmio_on('w', self._write_dma_status, CE + DMA_STATUS, CE + DMA_STATUS + 3)
        core._mmio_on('w', lambda *a: self._write_sha_control(core, *a), CE + SHA_CTRL, CE + SHA_CTRL + 3)
        core._mmio_on('w', self._write_sha_status, CE + SHA_STATUS, CE + SHA_STATUS + 3)
        core._mmio_on('w', self._write_sha_index, CE + SHA_INDEX, CE + SHA_INDEX + 3)

    @staticmethod
    def _first_time(core, uc, address, value):
        """Whether this start is new, not the replay of a rewound store (simulator._dev_replay_of)."""
        if core._dev_replay_of(uc, 'ce', address, value) is not None:
            return False
        core._dev_note(uc, 'ce', address, value)
        return True

    def _rd(self, offset):
        return int.from_bytes(self.sim.peek(0xB8000000 + CE + offset, 4), 'little')

    def _wr(self, offset, value):
        self.sim.poke(0xB8000000 + CE + offset, struct.pack("<I", value & 0xFFFFFFFF))

    def _data(self, address, length):
        """`length` bytes of the RAM at the physical `address`."""
        ram, size = self.sim.ram_buffer, self.sim.ram_size
        a = address % size
        length = min(length, 0x4000000)
        if a + length <= size:
            return bytes(memoryview(ram)[a:a + length])
        return bytes(memoryview(ram)[a:]) + bytes(memoryview(ram)[:a + length - size])

    def _hash(self, data):
        algorithm = ALGORITHMS.get(self._rd(SHA_CTRL) >> 29, "sha256")
        digest = hashlib.new(algorithm, data).digest()
        self.digest = list(struct.unpack(f">{len(digest) // 4}I", digest))
        self.jobs += 1
        self._wr(SHA_STATUS, self._rd(SHA_STATUS) | 1)
        self._show_word(self._rd(SHA_INDEX))

    def _show_word(self, index_reg):
        i = index_reg & 0xF
        self._wr(SHA_WORD, self.digest[i] if i < len(self.digest) else 0)

    def _write_dma_control(self, core, uc, access, address, size, value, user_data):
        word, shift, mask = _merge(uc, address, size, value)
        if word & DMA_START and self._first_time(core, uc, address, value):
            if self._rd(SHA_INDEX) & SHA_FROM_DMA:
                self._hash(self._data(self._rd(DMA_SRC) & 0x1FFFFFFF, self._rd(DMA_LEN)))
            self._wr(DMA_STATUS, (self._rd(DMA_STATUS) | DMA_DONE) & ~0x100)
        landed = word & ~DMA_START
        self._update_line(landed)           # (the enables the ISR clears drop the line too)
        return (landed & mask) >> shift

    def _write_dma_status(self, uc, access, address, size, value, user_data):
        word, shift, mask = _merge(uc, address, size, value)
        status = self._rd(DMA_STATUS) & ~(((value << shift) & mask) & 0x3F)
        self._wr(DMA_STATUS, status)
        self._update_line()
        return (status & mask) >> shift

    def _write_sha_control(self, core, uc, access, address, size, value, user_data):
        word, shift, mask = _merge(uc, address, size, value)
        if not word & 1:
            return None
        if self._first_time(core, uc, address, value):
            self._wr(SHA_CTRL, word)
            self._hash(self._data(self._rd(SHA_SRC) & 0x1FFFFFFF, self._rd(SHA_LEN)))
        return ((word & ~1) & mask) >> shift

    def _write_sha_status(self, uc, access, address, size, value, user_data):
        word, shift, mask = _merge(uc, address, size, value)
        status = self._rd(SHA_STATUS) & ~(((value << shift) & mask) & 1)
        return (status & mask) >> shift

    def _write_sha_index(self, uc, access, address, size, value, user_data):
        word, shift, mask = _merge(uc, address, size, value)
        self._show_word(word)
        return None

    def _cores(self):
        cores = [self.sim]
        see = getattr(self.sim.chip, "see", None)
        core = getattr(getattr(see, "core", None), "core", None)
        if core is not None:
            cores.append(core)
        return cores

    def _update_line(self, control=None):
        control = self._rd(DMA_CTRL) if control is None else control
        on = bool(self._rd(DMA_STATUS) & (control >> 8) & 0x3F)
        for core in self._cores():
            enables = int.from_bytes(core.peek(core._ic + 8 + 4 * (CE_LINE // 32), 4), 'little')
            on_here = on and bool(enables >> (CE_LINE % 32) & 1)
            if on_here or core._ic_lines >> CE_LINE & 1:
                core._ic_set_line(CE_LINE, on_here)
