"""The interface of a chip family (see chips/__init__.py), and register models
several families share (DemodulatorLock, ReadyBits)."""
import hashlib
import lzma
import struct

from unicorn.mips_const import UC_MIPS_REG_PC


def chunk_chain(image, limit=40):
    """The ALi chunk chain from offset 0 of a flash image: [(offset, name,
    version)], each chunk header being id, length, offset of the next chunk,
    CRC (big-endian words) and the name / version strings at +0x10 / +0x20."""
    out, q = [], 0
    while q + 0x40 <= len(image) and len(out) < limit:
        cid, length, nxt, _crc = struct.unpack_from(">IIII", image, q)
        if cid in (0, 0xFFFFFFFF) or length > len(image):
            break
        text = lambda o: bytes(image[q + o:q + o + 0x10]).split(b"\0", 1)[0].decode("latin-1")   # noqa: E731
        out.append((q, text(0x10), text(0x20)))
        if nxt == 0:
            after = q + length + 0x80
            if q == 0 and 0 < after <= len(image) - 0x40 and struct.unpack_from(">I", image, after)[0] not in (0, 0xFFFFFFFF):
                nxt = after
            else:
                break
        q += nxt
    return out


_maincode_cache = (None, b"")


def maincode(image):
    """The image's maincode chunk unpacked (its LZMA-alone payload after the
    0x80-byte chunk header), b"" when there is none or it does not unpack.
    The last result is kept: several families may ask about one image."""
    global _maincode_cache
    key = (len(image), hashlib.sha1(bytes(image[:0x40000])).digest())
    if _maincode_cache[0] == key:
        return _maincode_cache[1]
    data = b""
    for offset, name, _version in chunk_chain(image):
        if name.lower() == "maincode":
            length = struct.unpack_from(">I", image, offset + 4)[0]
            try:
                data = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
                    bytes(image[offset + 0x80:offset + 0x80 + length]))
            except lzma.LZMAError:
                data = b""
            break
    _maincode_cache = (key, data)
    return data


class DemodulatorLock:
    """A demodulator's lock status, as the driver's get_lock() and channel
    monitor read it: with `signal` on -- and the tuner on a frequency with a
    signal (sim.tuned_to_signal) -- each register of LOCKED reads as its
    function makes it of the byte last written there; with it off the
    registers are RAM, the driver's own values (no lock).  A family's model
    gives BASE, the register block's offset in the device window, and
    LOCKED, {register: f(byte) -> byte}."""
    BASE = 0
    LOCKED = {}

    def __init__(self, sim):
        self.sim = sim
        self.signal = False
        self.lock_reads = 0             # reads of those registers: a test can tell the driver asked
        for reg in self.LOCKED:
            sim._mmio_on('r', self._read, self.BASE + reg, self.BASE + reg)

    def _read(self, uc, access, address, size, value, user_data):
        self.lock_reads += 1
        if not self.signal or not self.sim.tuned_to_signal():
            return
        start = (address & 0xFFFFFF) - self.BASE
        data = bytearray(uc.mem_read(address, size))
        for i in range(size):
            f = self.LOCKED.get(start + i)
            if f:
                data[i] = f(data[i]) & 0xFF
        uc.mem_write(address, bytes(data))


class ReadyBits:
    """Status bits a firmware polls until the hardware reports ready, which the
    simulator's hardware is at once: {register offset in the device window (a
    byte): the bits that always read as set}.  A read of any size that covers
    such a byte sees them -- a word read of its register too."""
    def __init__(self, sim, bits):
        self.bits = bits
        starts = set()
        for offset in bits:
            starts.update(range(offset & ~3, offset + 1))      # word, halfword and byte reads that cover it
        for start in sorted(starts):
            sim._mmio_on('r', self._read, start, start)

    def _read(self, uc, access, address, size, value, user_data):
        start = address & 0xFFFFFF
        data = bytearray(uc.mem_read(address, size))
        for i in range(size):
            data[i] |= self.bits.get(start + i, 0)
        uc.mem_write(address, bytes(data))


class ChipFamily:
    """What a family adds to the common simulator: override what differs."""
    name = "ALi"
    chip_id = 0x0000            # the chip ID word at 0xB8000000 the firmware's chip-ID function
    chip_variant = 0x0000       # reads: the 16-bit ID in the upper half, variant bits in the lower
    dmx = None                  # the family's demultiplexer model (dmx_m36.Demux), for sim.attach_mux
    demod = None                # the family's demodulator model (a DemodulatorLock), for sim.set_signal
    see = None                  # a dual-CPU chip's SEE co-processor (see.SeeStart), reset by loadFile
    ve_status = True            # the video engine's +0x28 / +0x88 are status words (simulator._hook_ve_status_read)
    core_devices = ()           # device models a dual-CPU chip's second core reaches too (their wire(core))

    def __init__(self, sim):
        self.sim = sim

    @classmethod
    def matches(cls, image):
        """Whether a flash image (bytes) is this family's."""
        return False

    def install(self):
        """Memory and devices of this family, on top of the common ones; called
        once when the simulator (or loadFile) switches to the family."""
        self.write_chip_id()

    def uninstall(self):
        """Give back what install() changed besides the device register
        handlers and slice services, which the simulator resets itself when it
        switches to another family (simulator._switch_family): memory mapped
        over the flash window or above the RAM, Unicorn hooks, simulator
        attributes.  Nothing here."""

    def write_chip_id(self):
        """The chip ID word at 0xB8000000: the 16-bit ID in its upper half --
        the family's, or the loaded board's own where the family's members read
        different ones (its sidecar's device.chipId) -- the variant bits below."""
        self.chip_id = type(self).chip_id
        path = getattr(self.sim, "dump_path", None)
        if path:
            import dump_catalog
            self.chip_id = dump_catalog.chip_id(path) or self.chip_id
        self.sim.poke(0xB8000000, ((self.chip_id << 16) | self.variant()).to_bytes(4, 'little'))

    def variant(self):
        """The variant bits under the chip ID (chip_variant; a family whose
        members differ there picks them by self.chip_id)."""
        return self.chip_variant

    def start(self):
        """The reset state once an image is in the flash: where the CPU starts
        (after whatever the chip's boot ROM did before handing over)."""
        self.sim.mu.reg_write(UC_MIPS_REG_PC, self.sim.base_addr)

    def set_signal(self, on):
        """Make the family's demodulator report a locked channel (on) or not.
        Returns False when the family has no demodulator model."""
        if self.demod is None:
            return False
        self.demod.signal = bool(on)
        return True

    def code_ranges(self):
        """Memory besides RAM and flash that holds code: [(address, length)] in the
        0x80000000 view, scanned for CP0 instruction sites like RAM is."""
        return []
