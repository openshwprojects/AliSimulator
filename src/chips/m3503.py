"""
ALi M3503 (dumps/GLOBO HD-XS2/: the Globo HD-XS2 / Opticum Blue XS65
satellite updates), a dual-CPU chip of the S3602 platform: its main code is
the SDK's "M3602 HD STB" build with the chip's own DVB-S2 demodulator
(NIM_S3503), so it is the M36xx family (m3602.py: its devices and the SEE
start handshake, see.py) with the chip ID 0x3503.

Its bootloader is the XIP kind of the Ferguson T750i's (m3821.py): it runs
from the flash window -- the word at 0x490, where the chunk header's branch
lands, calls into it -- and keeps its stack in locked D-cache lines at
0x8FFF8000..0x8FFFFFFF until the DDR is up (CacheAsRam).  Without that RAM
it pops a return address of 0xFFFFFFFF from the flash and ends at PC 0.
Bootloader and application are silent retail builds: one 0x01 byte to the
UART at the start, nothing else.

Recognised by the bootloader chunk's version, "M3503---0.1.0".
"""
from .base import chunk_chain
from .m3602 import M3602
from .m3821 import CacheAsRam


class M3503(M3602):
    name = "M3503"
    chip_id = 0x3503

    @classmethod
    def matches(cls, image):
        return any(name == "bootloader" and version.startswith("M3503")
                   for _offset, name, version in chunk_chain(image))

    def install(self):
        super().install()
        self.car = CacheAsRam(self.sim)
