"""The interface of a chip family (see chips/__init__.py)."""
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
            break
        q += nxt
    return out


class ChipFamily:
    """What a family adds to the common simulator: override what differs."""
    name = "ALi"
    chip_id = 0x0000            # the chip ID word at 0xB8000000 the firmware's chip-ID function
    chip_variant = 0x0000       # reads: the 16-bit ID in the upper half, variant bits in the lower

    def __init__(self, sim):
        self.sim = sim

    @classmethod
    def matches(cls, image):
        """Whether a flash image (bytes) is this family's."""
        return False

    def install(self):
        """Memory and devices of this family, on top of the common ones; called
        once when the simulator (or loadFile) switches to the family."""
        self.sim.poke(0xB8000000, ((self.chip_id << 16) | self.chip_variant).to_bytes(4, 'little'))

    def start(self):
        """The reset state once an image is in the flash: where the CPU starts
        (after whatever the chip's boot ROM did before handing over)."""
        self.sim.mu.reg_write(UC_MIPS_REG_PC, self.sim.base_addr)

    def set_signal(self, on):
        """Make the family's demodulator report a locked channel (on) or not.
        Returns False when the family has no demodulator model."""
        return False

    def code_ranges(self):
        """Memory besides RAM and flash that holds code: [(address, length)] in the
        0x80000000 view, scanned for CP0 instruction sites like RAM is."""
        return []
