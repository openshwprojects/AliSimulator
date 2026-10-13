"""
ALi M3503 (dumps/GLOBO HD-XS2/: the Globo HD-XS2 / Opticum Blue XS65
satellite updates), a dual-CPU chip of the S3602 platform: its main code is
the SDK's "M3602 HD STB" build with the chip's own DVB-S2 demodulator
(NIM_S3503), so it is the M36xx family (m3602.py: its devices and the SEE,
see.py -- the start handshake and the SEE's program on a second core, here
with the newer chips' doorbells) with the chip ID 0x3503.

Its bootloader is the XIP kind of the Ferguson T750i's (m3821.py): it runs
from the flash window -- the word at 0x490, where the chunk header's branch
lands, calls into it -- and keeps its stack in locked D-cache lines at
0x8FFF8000..0x8FFFFFFF until the DDR is up (CacheAsRam).  Without that RAM
it pops a return address of 0xFFFFFFFF from the flash and ends at PC 0.
Bootloader and application are silent retail builds: one 0x01 byte to the
UART at the start, nothing else.

The chip's DVB-S2 demodulator is on the chip (InternalDemod): the CPU reads
its registers directly at 0xB8028000 + the register number.

The Echosonic Mini ESR-250's M3510A runs as this family too: its bootloader
("3510-r1362") is the same XIP kind with the same cache-as-RAM stack, its
set-up code branches on the chip IDs 0x3503 and 0x3821 (0x3510 appears
nowhere in it), and its application -- single-CPU, no SEE program --
drives the same internal demodulator.

Recognised by the bootloader chunk's version, "M3503---0.1.0" or "3510-".
"""
from demods import S3501

from .base import chunk_chain
from .m3602 import M3602
from .m3821 import CacheAsRam


class InternalDemod:
    """The chip's own DVB-S2 demodulator (the NIM_S3503 / NIM_S3501 drivers):
    an S3501 core whose registers the CPU reaches at 0xB8028000 + the
    register number instead of over I2C.  The chip ID registers 0xA3..0xA6
    read the S3501's ID (demods.S3501.ID, 0x350100C0 as the driver assembles
    it) and keep it; the others keep what is stored.  A task of the
    ESR-250's application asks the NIM device for that ID over and over
    (0x8032FC88) and hid the OSD layer (0xB8006300 bit 0) while its upper
    half was not 0x3501, although the application had drawn its Quick Setup
    menu."""
    BASE = 0x28000

    def __init__(self, sim):
        self.sim = sim
        sim.poke(0xB8000000 + self.BASE + 0xA3, bytes(S3501.ID[r] for r in sorted(S3501.ID)))
        sim._mmio_on('w', self._write, self.BASE + 0xA0, self.BASE + 0xA6)

    def _write(self, uc, access, address, size, value, user_data):
        reg = address & 0xFF
        return sum(S3501.ID.get(reg + i, (value >> (8 * i)) & 0xFF) << (8 * i) for i in range(size))

    def remove(self):
        """The ID registers back to zero (the next family's chip has no such demodulator)."""
        self.sim.poke(0xB8000000 + self.BASE + 0xA3, bytes(len(S3501.ID)))


class M3503(M3602):
    name = "M3503"
    chip_id = 0x3503

    @classmethod
    def matches(cls, image):
        return any(name == "bootloader" and version.startswith(("M3503", "3510-"))
                   for _offset, name, version in chunk_chain(image))

    def install(self):
        super().install()
        self.car = CacheAsRam(self.sim)
        self.nim = InternalDemod(self.sim)

    def uninstall(self):
        self.car.remove()
        self.nim.remove()
        super().uninstall()
