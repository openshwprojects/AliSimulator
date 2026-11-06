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

Recognised by the bootloader chunk's version, "M3503---0.1.0", "3510-", "M3510",
"M3511", "M3515" or "M3516".
"""
import ctypes

from uc_const import UC_PROT_ALL

from demods import S3501

from .base import REMAP_CTRL, UpperRamMixin, chunk_chain, uses_256m_ddr
from .m3602 import M3602
from .m3821 import CacheAsRam


class InternalDemod:
    """The chip's own DVB-S2 demodulator (the NIM_S3503 / NIM_S3501 / NIM_S3501H
    drivers): an S3501 core whose registers the CPU reaches at 0xB8028000 (or
    0xB804C000 on C3503/C3507) + the register number instead of over I2C.  The
    chip ID registers 0xA3..0xA6 and 0x140..0x143 read the S3501's ID
    (demods.S3501.ID, 0x350100C0 as the driver assembles it) and keep it; the
    others keep what is stored.  A task of the ESR-250's and C3507's
    applications asks the NIM device for that ID over and over and hid the OSD
    layer (0xB8006300 bit 0) while its upper half was not 0x3501, although the
    application had drawn its menu."""
    BASE = 0x28000
    ID_140 = {0x140: 0xC0, 0x141: 0x00, 0x142: 0x01, 0x143: 0x35}

    def __init__(self, sim, base=BASE):
        self.sim = sim
        self.base = base
        self.signal = False
        sim.poke(0xB8000000 + self.base + 0xA3, bytes(S3501.ID[r] for r in sorted(S3501.ID)))
        sim.poke(0xB8000000 + self.base + 0x140, bytes(self.ID_140[r] for r in sorted(self.ID_140)))
        sim._mmio_on('w', self._write, self.base + 0xA0, self.base + 0xA6)
        sim._mmio_on('w', self._write, self.base + 0x140, self.base + 0x143)
        for r in S3501.LOCK_REGS:
            sim._mmio_on('r', self._read_status, self.base + r, self.base + r)

    def locked(self):
        return self.signal and self.sim.tuned_to_signal()

    def set_signal(self, on=True):
        self.signal = bool(on)
        if not self.signal:
            b = self.sim._mmio_view[self.base + 0x04]
            self.sim._mmio_view[self.base + 0x04] = b & ~0x3F

    def _read_status(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        locked = self.locked()
        for i in range(size):
            off = (address + i) & 0xFFFFFF
            reg = off & 0xFF
            b = self.sim._mmio_view[off]
            if reg == 0x04:
                self.sim._mmio_view[off] = (b | 0x3F) if locked else (b & ~0x3F)
            elif locked:
                if reg == 0x68:
                    self.sim._mmio_view[off] = (b & 0xFC) | 0x01
                elif reg == 0x6B:
                    self.sim._mmio_view[off] = 0x68
                elif reg in S3501.LOCK_REGS and b == 0:
                    self.sim._mmio_view[off] = S3501.LOCK_REGS[reg]

    def _write(self, uc, access, address, size, value, user_data):
        reg = (address - self.base) & 0xFFF
        ids = S3501.ID | self.ID_140
        return sum(ids.get(reg + i, (value >> (8 * i)) & 0xFF) << (8 * i) for i in range(size))

    def remove(self):
        """The ID registers back to zero (the next family's chip has no such demodulator)."""
        self.sim.poke(0xB8000000 + self.base + 0xA3, bytes(len(S3501.ID)))
        self.sim.poke(0xB8000000 + self.base + 0x140, bytes(len(self.ID_140)))
        for r in S3501.LOCK_REGS:
            self.sim._mmio_view[self.base + r] = 0


class M3503(UpperRamMixin, M3602):
    name = "M3503"
    chip_id = 0x3503
    remapped_flash_base = "0xBF000000"

    @classmethod
    def matches(cls, image):
        return any(name.lower() == "bootloader" and version.startswith(("M3503", "3510-", "M3510", "M3511", "M3515", "M3516"))
                   for _offset, name, version in chunk_chain(image))

    def variant(self):
        # Newer M3503-family SoCs (M3510B on the Amiko Impulse SAT, M3511 / M3511D
        # on the Opticum XS65 Twin and Amiko HD8150, M3515 on the Opticum XS65
        # Combo, M3516A on the Amiko HD8260+) are M3503 revision B (low byte 1 ->
        # sys_ic_get_rev_id() returns 0x20002 instead of rev A's 0x20001; under
        # rev A the SDK's capability check disables GMA layer 0).
        if getattr(self, "_ram_256m", False) or (
            self.sim.rom_image and any(
                name.lower() == "bootloader" and version.startswith(("M3510B", "M3511", "M3515", "M3516"))
                for _o, name, version in chunk_chain(self.sim.rom_image)
            )
        ):
            return 0x0001
        return super().variant()

    def install(self):
        sim = self.sim
        self._ram_256m = bool(sim.rom_image) and uses_256m_ddr(sim.rom_image)
        sim._mmio_view[REMAP_CTRL + 3] &= ~0x01
        sim.set_upper_ram_mapped(False)
        sim.set_ram_size(0x10000000 if self._ram_256m else 0x08000000)
        super().install()
        self.car = CacheAsRam(sim)
        self._car_mapped = True
        self.write_chip_id()
        self.nim = self.demod = InternalDemod(sim)
        self._install_upper_ram_and_scb3()
        # the crypto engine's DMA and SHA unit, which the SEE's program hashes the application with
        from crypto_engine import CryptoEngine
        self.ce = CryptoEngine(sim)
        self.core_devices = self.core_devices + (self.ce,)

    def _configure_memory(self):
        sim = self.sim
        self._ram_256m = bool(sim.rom_image) and uses_256m_ddr(sim.rom_image)
        target = 0x10000000 if self._ram_256m else 0x08000000
        sim._mmio_view[REMAP_CTRL + 3] &= ~0x01
        if self._car_mapped:
            self.car.remove()
            self._car_mapped = False
        if sim.ram_size != target or sim._upper_ram_mapped:
            for address, size in self._ram_mirrors():
                sim.mu.mem_unmap(address, size)
            sim.set_upper_ram_mapped(False)
            sim.set_ram_size(target)
            ptr = ctypes.addressof(sim.ram_buffer)
            for address, size in self._ram_mirrors():
                sim.mu.mem_map_ptr(address, size, UC_PROT_ALL, ptr)
        self.car = CacheAsRam(sim)
        self._car_mapped = True
        self.write_chip_id()

    def on_upper_ram_mapped(self, on):
        if on and self._car_mapped:
            if self.car.active:
                self.sim.mu.hook_del(self.car._hook)
                self.car.active = False
            self._car_mapped = False

    def start(self):
        self._configure_memory()
        super().start()

    def set_signal(self, on=True):
        super().set_signal(on)
        self.nim.set_signal(on)
        return True

    def uninstall(self):
        self._uninstall_upper_ram_and_scb3()
        if self._car_mapped:
            self.car.remove()
            self._car_mapped = False
        self.nim.remove()
        super().uninstall()
        self.sim.set_upper_ram_mapped(False)
        if self.sim.ram_size != 0x08000000:
            self.sim.set_ram_size(0x08000000)

