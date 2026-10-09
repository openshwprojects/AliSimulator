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
the driver asked.  frequency() decodes the channel the driver has tuned the
chip to from those registers (None before the first tune):
  * MxL603 family: RF = registers 0x11:0x10 / 64 MHz, bandwidth in 0x0F
    (0x20 / 0x21 / 0x22 = 6 / 7 / 8 MHz terrestrial);
  * MxL5007T: RF = registers 0x0E:0x0D / 64 MHz, bandwidth in 0x0C
    (0x15 / 0x2A / 0x3F = 6 / 7 / 8 MHz) -- Linux mxl5007t's encoding;
  * R820T: the PLL's LO = 2 x crystal x (N + SDM / 65536) / mixer divider
    (N from register 0x14, SDM from 0x16:0x15 unless powered down by
    register 0x12 bit 3, the divider 2 << register 0x10 bits 7..5, the
    reference halved by 0x10 bit 4), RF = LO - IF.  The crystal and IF are
    the firmware's, given in the sidecar's tunerModel (the Globo N3's R828
    reference driver: 16 MHz, IF 4.57 MHz for DVB-T 8 MHz); while the driver
    calibrates, the LO is a calibration frequency.
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


    FREQ_LO, FREQ_HI, BW_REG, BW_CODES = None, None, None, {}

    def frequency(self):
        """{"rf_hz", "bw_mhz"} of the channel tuned to, or None before the first tune."""
        word = (self.regs[self.FREQ_HI] << 8) | self.regs[self.FREQ_LO]
        if not word:
            return None
        return {"rf_hz": word * 1_000_000 // 64, "bw_mhz": self.BW_CODES.get(self.regs[self.BW_REG] & 0x3F)}


class MxL603(MaxLinear):
    STATUS = {0x2B: 0x03}               # RF synthesizer and reference locked
    FREQ_LO, FREQ_HI, BW_REG = 0x10, 0x11, 0x0F
    BW_CODES = {0x20: 6, 0x21: 7, 0x22: 8}          # terrestrial (register 0x0F & 0x3F)


class MxL5007T(MaxLinear):
    STATUS = {0xD8: 0x0F}               # RF (bits 3..2) and reference (bits 1..0) locked
    FREQ_LO, FREQ_HI, BW_REG = 0x0D, 0x0E, 0x0C
    BW_CODES = {0x15: 6, 0x2A: 7, 0x3F: 8}


class R820T:
    CHIP_ID = 0x69
    STATUS_REGS = 5                     # registers 0..4 read status, writes start at 5
    PLL_N = 0x14

    def __init__(self, xtal_hz=16_000_000, if_hz=4_570_000):
        self.xtal_hz, self.if_hz = xtal_hz, if_hz
        self.regs = bytearray(32)
        self.regs[0] = self.CHIP_ID
        self.regs[1] = 0x20             # an image-rejection ADC reading (any value lets the calibration settle)
        self.regs[2] = 0x40             # PLL locked
        self.regs[4] = 0x28             # VCO fine tune 2 (= the drivers' VCO_POWER_REF: no divider correction),
                                        # filter calibration code 8 (neither 0 nor 0xF)
        self.reads = collections.Counter()      # read length -> reads (5: calibration, 3: PLL lock, 2: IMR)
        self.writes = 0
        self.pll_set = False            # the driver has programmed the PLL (not just the initial array)

    def write(self, data):
        if data:
            if data[0] == self.PLL_N:
                self.pll_set = True
            for i, b in enumerate(data[1:]):
                reg = data[0] + i
                if self.STATUS_REGS <= reg < len(self.regs):
                    self.regs[reg] = b
                    self.writes += 1
        return True

    def frequency(self):
        """{"rf_hz", "lo_hz", "bw_mhz", "calibrating"} the PLL is set to, or None
        before the driver set it.  The image-rejection calibration runs with
        the antenna input off (register 0x05 bit 5, R828_IMR_Prepare's "air-in
        off") at ring-oscillator frequencies; the tune turns the input on."""
        if not self.pll_set:
            return None
        r = self.regs
        ref = self.xtal_hz // 2 if r[0x10] & 0x10 else self.xtal_hz
        nint = 4 * (r[self.PLL_N] & 0x3F) + (r[self.PLL_N] >> 6) + 13
        sdm = 0 if r[0x12] & 0x08 else (r[0x16] << 8) | r[0x15]
        vco = 2 * ref * (nint + sdm / 65536)
        lo = round(vco / (2 << ((r[0x10] >> 5) & 7)))
        return {"rf_hz": lo - self.if_hz, "lo_hz": lo, "bw_mhz": None, "calibrating": bool(r[0x05] & 0x20)}

    def read(self, n):
        self.reads[n] += 1
        return bytes(bitrev8(self.regs[i % len(self.regs)]) for i in range(n))


MODELS = {"mxl603": MxL603, "mxl5007t": MxL5007T, "r820t": R820T}


def make(chip, **config):
    """A new model of `chip` (a key of MODELS, as in a sidecar's tunerModel);
    config: the R820T's xtal_hz / if_hz."""
    return MODELS[chip.lower()](**config)


def describe(device):
    """One line for the report: the tuned frequency, or what the chip is doing."""
    if device is None:
        return None
    f = device.frequency()
    name = type(device).__name__
    if f is None:
        return f"{name}: not tuned"
    if f.get("calibrating"):
        return f"{name}: calibrating (LO {f['lo_hz'] / 1e6:.3f} MHz)"
    text = f"{f['rf_hz'] / 1e6:.3f} MHz"
    if f.get("bw_mhz"):
        text += f" / {f['bw_mhz']} MHz"
    if f.get("lo_hz"):
        text += f" (LO {f['lo_hz'] / 1e6:.3f})"
    return f"{name}: {text}"


def is_tuner(device):
    """Whether an I2C device is one of these tuner models."""
    return isinstance(device, (MaxLinear, R820T))
