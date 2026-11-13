"""
ALi M3801 (the DVB-T boxes: Comsat TE 1050 HD, Opticum N2, Globo N3, the
Cabletech, Strong and Ferguson dumps): the CPU boots straight from the flash
window, reset vector 0xBFC00000 / SYS_FLASH_BASE_ADDR 0xAFC00000, and the
firmware identifies the silicon as an S3811 (chip ID 0x3811).  Nearly
everything simulator.py models by default is this family's; what is added
here is the internal COFDM demodulator's lock status (Demodulator), the
transport-stream demultiplexer (dmx_m36.py) and the real-time clock
(rtc_m36.py).
"""
from .base import ChipFamily, DemodulatorLock


class Demodulator(DemodulatorLock):
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
    so only bit 1 reads set with a signal -- on the tuned frequency, when the
    signal is only on some (sim.tuned_to_signal)."""
    BASE = 0x3E000
    LOCKED = {0x02: lambda v: v | 0x02, 0x1D: lambda v: v | 0x60, 0x3B: lambda v: 1, 0x147: lambda v: 1}


class M3801(ChipFamily):
    name = "M3801"
    chip_id = 0x3811
    # The S3811's GMA colours, measured on a real box (revision 1, a Comsat TE
    # 1050 HD running the Maciej demo v4) and read from both original
    # applications' driver: on revision 1 a region head is a 0x280-byte block
    # whose +0x240 holds the RGB -> YCbCr matrix the layer's colours go through
    # (the originals write BT.709's for HD; all zero, every colour came out
    # black, alpha still working), and bit 19 of the layer's enable register
    # (0xB8006300 / 0xB8006380; the originals clear it) skips the matrix: the
    # ARGB1555 red, green and blue fields, a CLUT8 palette entry's bytes 2, 1,
    # 0, are taken as Cr, Y and Cb.  The screen capture shows both (gma_capture).
    gma_ycbcr_bit = 1 << 19
    gma_head_matrix = True

    @classmethod
    def matches(cls, image):
        return True                 # the default family (see chips.detect)

    def install(self):
        super().install()
        self.demod = Demodulator(self.sim)
        # the transport-stream demultiplexer DMX0 at 0xB8022000 (dmx_m36.py)
        from dmx_m36 import Demux
        self.dmx = Demux(self.sim)
        # the real-time clock at 0xB8018A00, which the UI's local time is read from (rtc_m36.py)
        from rtc_m36 import Rtc
        self.rtc = Rtc(self.sim)
