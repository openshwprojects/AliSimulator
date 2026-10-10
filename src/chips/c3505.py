"""
ALi C3505 (the Ferguson Ariva T760i update images): a dual-CPU chip whose
bootloader is built for the same on-chip boot ROM as the M3821's -- the
register script at 0x480.., the code at 0x800 copied into the boot SRAM at
0x1FE00000 and entered at 0x9FE00800 -- so it is the M3821 family with the
C3505's chip ID 0x3505.  The bootloader and the R265 Lite's are one generic
build (both know the chip IDs 0x3503, 0x3505 and 0x3821); the main code is
what names the chip ("ALI_C3505:0x%x", c3505_phy_set), so the family is
recognised by a boot-ROM bootloader whose image has a SEE program chunk and
whose main code names the C3505.

On that path the bootloader waits for bit 8 of 0xB8000300 (ReadyWord), then
unpacks and starts the application; the application starts the SEE
co-processor's program the way see.py describes, which the simulator does
not run, and then waits for the SEE's answers.  (The T760i receives DVB-T2
through an external AltoBeam ATBM7812; nothing of that is modelled.)
"""
import struct

from .base import chunk_chain, maincode
from .m3821 import M3821
from .see import SeeStart

BOOTROM_SP = struct.pack("<I", 0x3C1D9FE0)     # lui $sp, 0x9FE0: a bootloader that runs in the boot SRAM


class ReadyWord:
    """Bits of a status word the bootloader polls until the hardware reports
    ready, which the simulator's hardware is at once: a word read starting at
    `offset` sees `bits` set (ReadyBits does the same for byte registers)."""
    def __init__(self, sim, offset, bits):
        self.offset, self.bits = offset, bits
        sim._mmio_on('r', self._read, offset, offset + 3)

    def _read(self, uc, access, address, size, value, user_data):
        word = (address & ~3)
        data = bytearray(uc.mem_read(word, 4))
        for i in range(4):
            data[i] |= (self.bits >> (8 * i)) & 0xFF
        uc.mem_write(word, bytes(data))


class C3505(M3821):
    name = "C3505"
    chip_id = 0x3505
    chip_variant = 0x0000

    @classmethod
    def matches(cls, image):
        if BOOTROM_SP not in (bytes(image[0x804:0x808]), bytes(image[0x808:0x80C])):
            return False                # not a boot-ROM bootloader
        if not any(name == "seecode" for _o, name, _v in chunk_chain(image)):
            return False                # (unpacking the main code is for the dual-CPU images only)
        return b"ALI_C3505" in maincode(image)

    def install(self):
        super().install()
        self.ready300 = ReadyWord(self.sim, 0x300, 0x00000100)     # bit 8: polled before the bootloader goes on
        self.see = SeeStart(self.sim)
