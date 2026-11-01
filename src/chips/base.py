"""The interface of a chip family (see chips/__init__.py), and register models
several families share (DemodulatorLock, ReadyBits)."""
import hashlib
import lzma
import struct

from unicorn.mips_const import UC_MIPS_REG_PC

REMAP_CTRL = 0x220                  # 0xB8000220: SEE control + bit 24 upper-DDR remap
REMAP_BIT = 0x01000000              # 0xB8000220 bit 24: 0x0F000000..0x0FFFFFFF is DDR (240..256 MB), not flash


def word_after_store(old, address, base, size, value):
    """A register word at `base` as a store of `size` bytes at `address` leaves it."""
    shift = 8 * ((address & 0xFFFFFF) - base)
    mask = ((1 << (8 * size)) - 1) << shift
    return (old & ~mask) | ((value << shift) & mask)


def count_lui(code, hi_val):
    """Count aligned MIPS `lui $r, hi_val` instructions in `code`."""
    hi = hi_val.to_bytes(2, "little")
    n = 0
    pos = code.find(hi)
    while pos >= 0:
        if (pos & 3) == 0 and pos + 4 <= len(code) and (code[pos + 3] >> 2) == 0x0F:
            n += 1
        pos = code.find(hi, pos + 1)
    return n


def uses_256m_ddr(image):
    """Whether a dual-CPU M3503 / C3505 image targets a 256 MB DDR layout: it
    has a `seecode` / `secseecode` chunk and compiles `SYS_FLASH_BASE_ADDR` as
    `0xBFC00000` instead of `0xAFC00000` so `0x0F000000..0x0FFFFFFF` can be
    remapped to DDR (240..256 MB) via `0xB8000220` bit 24."""
    if not any(name.lower() in ("seecode", "secseecode") for _o, name, _v in chunk_chain(image)):
        return False
    mc = maincode(image)
    return count_lui(mc, 0xBFC0) > count_lui(mc, 0xAFC0)


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
    mid = len(image) // 4
    key = (len(image), hashlib.sha1(bytes(image[:0x40000]) + bytes(image[mid:mid + 0x10000])).digest())
    if _maincode_cache[0] == key:
        return _maincode_cache[1]
    data = b""
    for offset, name, _version in chunk_chain(image):
        cid, length = struct.unpack_from(">II", image, offset)
        if name.lower().startswith("maincode") or (cid >> 16) == 0x01FE:
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
        attributes."""
        if self.see is not None:
            self.see.reset()

    def default_chip_id(self):
        """The 16-bit chip ID before any sidecar override (chip_id by default)."""
        return type(self).chip_id

    def write_chip_id(self):
        """The chip ID word at 0xB8000000: the 16-bit ID in its upper half --
        the family's, or the loaded board's own where the family's members read
        different ones (its sidecar's device.chipId) -- the variant bits below."""
        self.chip_id = self.default_chip_id()
        path = getattr(self.sim, "dump_path", None)
        if path:
            import dump_catalog
            cid = dump_catalog.chip_id(path)
            if cid is not None:
                self.chip_id = cid
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


class UpperRamMixin:
    """Fourth I2C master (`SCB3` at `0xB8018D00`) and 256 MB upper-DDR window
    remap (`0xB8000220` bit 24) shared by the M3503 and C3505 chip families."""
    remapped_flash_base = "0xBFC00000"

    def _install_upper_ram_and_scb3(self):
        import i2c_scb
        self.scb3 = i2c_scb.I2cMaster(self.sim, 0x18D00, "SCB3")
        self.sim.i2c_masters.append(self.scb3)
        self.sim._mmio_on('w', self._write_remap_ctrl, REMAP_CTRL, REMAP_CTRL + 3)

    def _uninstall_upper_ram_and_scb3(self):
        self._ram_256m = False
        self.sim._mmio_off('w', self._write_remap_ctrl, REMAP_CTRL, REMAP_CTRL + 3)
        if self.scb3 in self.sim.i2c_masters:
            self.sim.i2c_masters.remove(self.scb3)
        self.scb3.remove()

    def _write_remap_ctrl(self, uc, access, address, size, value, user_data):
        if not self._ram_256m:
            return
        old = int.from_bytes(self.sim.mmio_buffer[REMAP_CTRL:REMAP_CTRL + 4], 'little')
        new = word_after_store(old, address, REMAP_CTRL, size, value)
        if (old ^ new) & REMAP_BIT:
            on = bool(new & REMAP_BIT)
            self.sim.log(f"[{self.name}] 0xB8000220 bit 24 -> {int(on)}: 0x0F000000..0x0FFFFFFF is "
                         f"{'DDR (240..256 MB), flash at ' + self.remapped_flash_base if on else 'the flash window'}")
            self.sim.set_upper_ram_mapped(on)
