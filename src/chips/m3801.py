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
    The Comsat's channel monitor (dump.bin, 0x8039E01C / 0x803A1C00 /
    0x8039D194) wants more than the lock bits before it keeps a channel:
    register 0x3B must read exactly 1 (the demodulator's state) and
    register 0x147 non-zero; with 0x3B at 0 it polled it 400 times in 8 s
    and then stepped to the next channel.  With `signal` off the registers
    are RAM and read back what was written (0: no lock, the boxes show "no
    signal"); with it on, 0x1D reports the lock bits, 0x3B reads 1 and
    0x147 reads 1.  Register 0x02 is the demodulator's event / status flags
    (the driver reads it, clears a bit and writes it back): after a command
    through register 0x12E (bit 1) the Comsat's driver polls it up to a
    thousand times, 1 ms apart, for bit 1 or bit 0 -- "done" -- and reports
    the tune failed when neither comes (0x803A2060), which made it step to
    the next channel; bit 5 / bits 5-6 are "lock lost" events it reacts to,
    so only bit 1 reads set with a signal."""
    BASE = 0x3E000
    LOCK_REG, LOCK_BITS = 0x1D, 0x60
    LOCKED = {0x02: lambda v: v | 0x02, 0x1D: lambda v: v | 0x60, 0x3B: lambda v: 1, 0x147: lambda v: 1}

    def __init__(self, sim):
        self.sim = sim
        self.signal = False
        self.lock_reads = 0
        for reg in self.LOCKED:
            sim._mmio_on('r', self._read_lock, self.BASE + reg, self.BASE + reg)

    def _read_lock(self, uc, access, address, size, value, user_data):
        self.lock_reads += 1
        if not self.signal:
            return
        start = (address & 0xFFFFFF) - self.BASE
        data = bytearray(uc.mem_read(address, size))
        for i in range(size):
            f = self.LOCKED.get(start + i)
            if f:
                data[i] = f(data[i]) & 0xFF
        uc.mem_write(address, bytes(data))


class M3801(ChipFamily):
    name = "M3801"
    chip_id = 0x3811

    @classmethod
    def matches(cls, image):
        return True                 # the default family (see chips.detect)

    def install(self):
        super().install()
        self.demod = Demodulator(self.sim)
        # the transport-stream demultiplexer DMX0 at 0xB8022000 (dmx_m36.py)
        from dmx_m36 import Demux
        self.dmx = Demux(self.sim)

    def set_signal(self, on):
        self.demod.signal = bool(on)
        return True
