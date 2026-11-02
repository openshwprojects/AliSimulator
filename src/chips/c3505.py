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

On that path the bootloader waits for bit 8 of 0xB8000300 (ReadyBits), then
unpacks and starts the application; the application starts the SEE
co-processor's program the way see.py describes, which runs on a second
core (see.SeeCore) and answers its remote calls.  (The T760i receives
DVB-T2 through an external AltoBeam ATBM7812; nothing of that is modelled.)
"""
import struct

from .base import REMAP_CTRL, ReadyBits, UpperRamMixin, chunk_chain, maincode, uses_256m_ddr
from .m3503 import InternalDemod
from .m3821 import M3821

BOOTROM_SP = (
    struct.pack("<I", 0x3C1D9FE0),  # lui $sp, 0x9FE0: a bootloader that runs in the boot SRAM (KSEG0)
    struct.pack("<I", 0x3C1DBFE0),  # lui $sp, 0xBFE0: the same boot SRAM in KSEG1 (Ariva 104)
)


class C3505(UpperRamMixin, M3821):
    name = "C3505"
    chip_id = 0x3505
    chip_variant = 0x0000
    remapped_flash_base = "0xBF800000"

    @classmethod
    def matches(cls, image):
        if len(image) < 0x80C or not any(sp in (bytes(image[0x804:0x808]), bytes(image[0x808:0x80C])) for sp in BOOTROM_SP):
            return False                # not a boot-ROM bootloader
        if not any(name == "seecode" for _o, name, _v in chunk_chain(image)):
            return False                # (unpacking the main code is for the dual-CPU images only)
        mc = maincode(image)
        return any(tag in mc for tag in (b"ALI_C3505", b"NIM_C3505_0", b"NIM_S3505", b"DECV_HEVC_0"))

    def install(self):
        self._ram_256m = False
        super().install()
        self.ready300 = ReadyBits(self.sim, {0x301: 0x01})     # bit 8 of 0xB8000300: polled before the bootloader goes on
        self.nim = InternalDemod(self.sim)
        from video_m36 import VideoEngine, VideoOutputM36F
        from crypto_engine import CryptoEngine
        self.video_engine = VideoEngine(self.sim, reset=(0x80, 0x02))
        self.video_output = VideoOutputM36F(self.sim)
        self.ce = CryptoEngine(self.sim)
        self.core_devices = getattr(self, "core_devices", ()) + (self.dma, self.video_engine, self.video_output, self.ce)
        self._install_upper_ram_and_scb3()
        self._configure_memory()

    def _configure_memory(self):
        sim = self.sim
        self._ram_256m = bool(sim.rom_image) and uses_256m_ddr(sim.rom_image)
        sim._mmio_view[REMAP_CTRL + 3] &= ~0x01
        sim.set_upper_ram_mapped(False)
        sim.set_ram_size(0x10000000 if self._ram_256m else 0x08000000)

    def on_upper_ram_mapped(self, on):
        self._set_sram_mapped(not on)

    def start(self):
        self._configure_memory()
        super().start()

    def set_signal(self, on=True):
        super().set_signal(on)
        self.nim.set_signal(on)
        return True

    def uninstall(self):
        self._uninstall_upper_ram_and_scb3()
        self.sim.set_upper_ram_mapped(False)
        if self.sim.ram_size != 0x08000000:
            self.sim.set_ram_size(0x08000000)
        self.nim.remove()
        super().uninstall()

