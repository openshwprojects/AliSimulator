"""
ALi M3801 (the DVB-T boxes: Comsat TE 1050 HD, Opticum N2, Globo N3, the
Cabletech, Strong and Ferguson dumps): the CPU boots straight from the flash
window, reset vector 0xBFC00000 / SYS_FLASH_BASE_ADDR 0xAFC00000, and the
firmware identifies the silicon as an S3811 (chip ID 0x3811).  Nearly
everything simulator.py models by default is this family's; what is added
here is the internal COFDM demodulator's lock status (Demodulator).
"""
from .base import ChipFamily


class Demodulator:
    """The chip's own COFDM demodulator ("NIM_S3811_0"), its registers memory-
    mapped at 0xB803E000 + register (the nim_device's base address; the
    driver's register-read helper uses I2C only for an external demodulator).
    Its get_lock() reads register 0x1D and reports lock when bit 5 is set
    (Globo N3 application, 0x803D143C); another status function tests bit 6.
    The channel change restarts acquisition (+0x00 = 0x80 then 0xC0, +0x13,
    +0x1B) and the monitor reads +0x30 / +0x31 and +0x1E / +0x1F (levels).
    With `signal` off the registers are RAM and read back what was written
    (0: no lock, the boxes show "no signal"); with it on, register 0x1D
    reports the demodulator locked."""
    BASE = 0x3E000
    LOCK_REG, LOCK_BITS = 0x1D, 0x60

    def __init__(self, sim):
        self.sim = sim
        self.signal = False
        self.lock_reads = 0
        sim._mmio_on('r', self._read_lock, self.BASE + self.LOCK_REG, self.BASE + self.LOCK_REG)

    def _read_lock(self, uc, access, address, size, value, user_data):
        self.lock_reads += 1
        if self.signal:
            uc.mem_write(address, bytes([uc.mem_read(address, 1)[0] | self.LOCK_BITS]))


class M3801(ChipFamily):
    name = "M3801"
    chip_id = 0x3811

    @classmethod
    def matches(cls, image):
        return True                 # the default family (see chips.detect)

    def install(self):
        super().install()
        self.demod = Demodulator(self.sim)

    def set_signal(self, on):
        self.demod.signal = bool(on)
        return True
