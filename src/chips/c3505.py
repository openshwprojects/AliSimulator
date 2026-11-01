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

import i2c_scb
from .base import ReadyBits, chunk_chain, maincode
from .m3503 import InternalDemod
from .m3821 import M3821
from .see import CONTROL, SeeStart

BOOTROM_SP = (
    struct.pack("<I", 0x3C1D9FE0),  # lui $sp, 0x9FE0: a bootloader that runs in the boot SRAM (KSEG0)
    struct.pack("<I", 0x3C1DBFE0),  # lui $sp, 0xBFE0: the same boot SRAM in KSEG1 (Ariva 104)
)
REMAP_BIT = 0x01000000              # 0xB8000220 bit 24 (0xB8000223 bit 0): 0x0F000000..0x0FFFFFFF is DDR, not flash


def _is_256m(image):
    """A 256 MB C3505 build (Ariva 255 Combo): its maincode sets
    SYS_FLASH_BASE_ADDR to 0xBFC00000 (lui rX, 0xBFC0) and uses
    0xAF000000..0xB0000000 as the top 16 MB of DDR once the bootloader sets
    0xB8000220 bit 24."""
    mc = maincode(image)
    pos = mc.find(b"\xC0\xBF")
    while pos >= 0:
        if (pos & 3) == 0 and pos + 4 <= len(mc) and (mc[pos + 3] >> 2) == 0x0F:
            return True
        pos = mc.find(b"\xC0\xBF", pos + 1)
    return False


class C3505(M3821):
    name = "C3505"
    chip_id = 0x3505
    chip_variant = 0x0000

    @classmethod
    def matches(cls, image):
        if not any(sp in (bytes(image[0x804:0x808]), bytes(image[0x808:0x80C])) for sp in BOOTROM_SP):
            return False                # not a boot-ROM bootloader
        if not any(name == "seecode" for _o, name, _v in chunk_chain(image)):
            return False                # (unpacking the main code is for the dual-CPU images only)
        mc = maincode(image)
        return any(tag in mc for tag in (b"ALI_C3505", b"NIM_C3505_0", b"NIM_S3505"))

    def install(self):
        self._ram_256m = False
        super().install()
        self.ready300 = ReadyBits(self.sim, {0x301: 0x01})     # bit 8 of 0xB8000300: polled before the bootloader goes on
        self.nim = InternalDemod(self.sim)
        self.scb3 = i2c_scb.I2cMaster(self.sim, 0x18D00, "SCB3")
        self.sim.i2c_masters.append(self.scb3)
        self.sim._mmio_on('w', self._write_remap_ctrl, CONTROL, CONTROL + 3)
        self._configure_memory()

    def _configure_memory(self):
        sim = self.sim
        self._ram_256m = bool(sim.rom_image) and _is_256m(sim.rom_image)
        sim._mmio_view[CONTROL + 3] &= ~0x01
        sim.set_upper_ram_mapped(False)
        sim.set_ram_size(0x10000000 if self._ram_256m else 0x08000000)

    def _write_remap_ctrl(self, uc, access, address, size, value, user_data):
        if not self._ram_256m:
            return
        old = int.from_bytes(self.sim.mmio_buffer[CONTROL:CONTROL + 4], 'little')
        new = SeeStart._after(old, address, CONTROL, size, value)
        if (old ^ new) & REMAP_BIT:
            on = bool(new & REMAP_BIT)
            self.sim.log(f"[C3505] 0xB8000220 bit 24 -> {int(on)}: 0x0F000000..0x0FFFFFFF is "
                         f"{'DDR (240..256 MB), flash at 0xBF800000' if on else 'the flash window'}")
            self.sim.set_upper_ram_mapped(on)

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
        self._ram_256m = False
        self.sim._mmio_off('w', self._write_remap_ctrl, CONTROL, CONTROL + 3)
        if self.scb3 in self.sim.i2c_masters:
            self.sim.i2c_masters.remove(self.scb3)
        self.scb3.remove()
        self.sim.set_upper_ram_mapped(False)
        if self.sim.ram_size != 0x08000000:
            self.sim.set_ram_size(0x08000000)
        self.nim.remove()
        super().uninstall()

