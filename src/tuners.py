"""
Tuner chip models for the hardware I2C masters (i2c_scb.py): what a
firmware's tuner driver sees of a real tuner that takes its settings and
locks.  Which chip a box has, and at which 7-bit address, is its dump
sidecar's device.tunerModel (dump_catalog.py); sim.attach_tuner() puts that
chip on the bus.  Without it no tuner answers, as before, and the drivers
give up at once.

  * MaxLinear (MxL5007T, the MxL603 family -- MxL603 and the pin-compatible
    MxL608): a write is a sequence of (register, value) pairs, and the pair
    (0xFB, r) selects register r for the next one-byte read.  The lock status
    is MxL603 register 0x2B (bit 0 RF synthesizer, bit 1 reference: the
    Strong SRT 8115's driver, 0x80256AE8) and MxL5007T register 0xD8 (bits
    3..2 RF, 1..0 reference, as Linux's mxl5007t tests them; the 2012
    URZ0195 firmware stops re-tuning once it reads 0x0F there).
  * Rafael Micro R820T: a write sets the register address (its first byte)
    and the registers from there on; a read starts at register 0 whatever
    was written and sends every byte bit-reversed.  Registers 0..4 are
    status: 0 the chip id (0x69), 2 bit 6 the PLL lock, 4 bits 3..0 the
    filter calibration code (0 and 0xF mean the calibration failed), 1 bits
    5..0 the image-rejection ADC the calibration minimises.

Each model keeps what was written (the drivers read registers back to change
a few bits) and counts the reads of every status register, so a test can tell
the driver asked.
"""
import collections


def bitrev8(b):
    return int(f"{b:08b}"[::-1], 2)


class MaxLinear:
    """The MaxLinear register protocol; STATUS = {register: value it reads as}."""
    READ_PREFIX = 0xFB
    STATUS = {}

    def __init__(self):
        self.regs = bytearray(256)
        self.read_reg = 0
        self.reads = collections.Counter()      # register -> reads
        self.writes = 0

    def write(self, data):
        for i in range(0, len(data) - 1, 2):
            reg, value = data[i], data[i + 1]
            if reg == self.READ_PREFIX:
                self.read_reg = value
            else:
                self.regs[reg] = value
                self.writes += 1
        return True

    def read(self, n):
        self.reads[self.read_reg] += 1
        value = self.STATUS.get(self.read_reg, self.regs[self.read_reg])
        return bytes([value]) + bytes(max(0, n - 1))


class MxL603(MaxLinear):
    STATUS = {0x2B: 0x03}               # RF synthesizer and reference locked


class MxL5007T(MaxLinear):
    STATUS = {0xD8: 0x0F}               # RF (bits 3..2) and reference (bits 1..0) locked


class R820T:
    CHIP_ID = 0x69
    STATUS_REGS = 5                     # registers 0..4 read status, writes start at 5

    def __init__(self):
        self.regs = bytearray(32)
        self.regs[0] = self.CHIP_ID
        self.regs[1] = 0x20             # an image-rejection ADC reading (any value lets the calibration settle)
        self.regs[2] = 0x40             # PLL locked
        self.regs[4] = 0x08             # filter calibration code: neither 0 nor 0xF
        self.reads = collections.Counter()      # read length -> reads (5: calibration, 3: PLL lock, 2: IMR)
        self.writes = 0

    def write(self, data):
        if data:
            for i, b in enumerate(data[1:]):
                reg = data[0] + i
                if self.STATUS_REGS <= reg < len(self.regs):
                    self.regs[reg] = b
                    self.writes += 1
        return True

    def read(self, n):
        self.reads[n] += 1
        return bytes(bitrev8(self.regs[i % len(self.regs)]) for i in range(n))


MODELS = {"mxl603": MxL603, "mxl5007t": MxL5007T, "r820t": R820T}


def make(chip):
    """A new model of `chip` (a key of MODELS, as in a sidecar's tunerModel)."""
    return MODELS[chip.lower()]()


def is_tuner(device):
    """Whether an I2C device is one of these tuner models."""
    return isinstance(device, (MaxLinear, R820T))
