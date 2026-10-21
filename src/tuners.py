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


class MxL608(MxL603):
    pass


class MxL5007T(MaxLinear):
    STATUS = {0xD3: 0x14, 0xD8: 0x0F}   # 0xD3: MxL_5007T_V4 chip version; 0xD8: RF (bits 3..2) and reference (bits 1..0) locked
    FREQ_LO, FREQ_HI, BW_REG = 0x0D, 0x0E, 0x0C
    BW_CODES = {0x15: 6, 0x2A: 7, 0x3F: 8}


class MxL101SF(MaxLinear):
    """MaxLinear MxL101SF single-chip DVB-T tuner+demodulator (URZ0086, KM0186,
    THT501, X110TS): uses the 0xFB read prefix; chip ID 0x61 in 0xFC, version
    0x09 in 0xFA, CP lock >= 0x1841 in 0x26:0x25, RS/MPEG/TPS lock in 0x28,
    TPS cell ID lock in 0x2A, RF in 0x1F:0x1E / 64 MHz, bandwidth in 0x1D."""
    STATUS = {0x03: 0x01, 0x25: 0x42, 0x26: 0x18, 0x28: 0x0E, 0x2A: 0x08, 0xFA: 0x09, 0xFC: 0x61}
    FREQ_LO, FREQ_HI, BW_REG = 0x1E, 0x1F, 0x1D
    BW_CODES = {0x15: 6, 0x2A: 7, 0x3F: 8}


class R820T:
    CHIP_ID = 0x69
    STATUS_REGS = 5                     # registers 0..4 read status, writes start at 5
    NUM_REGS = 32
    PLL_N = 0x14
    REF_DIV_BIT = 0x10

    def __init__(self, xtal_hz=16_000_000, if_hz=4_570_000):
        self.xtal_hz, self.if_hz = xtal_hz, if_hz
        self.regs = bytearray(self.NUM_REGS)
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
        ref = self.xtal_hz // 2 if r[0x10] & self.REF_DIV_BIT else self.xtal_hz
        nint = 4 * (r[self.PLL_N] & 0x3F) + (r[self.PLL_N] >> 6) + 13
        sdm = 0 if r[0x12] & 0x08 else (r[0x16] << 8) | r[0x15]
        vco = 2 * ref * (nint + sdm / 65536)
        lo = round(vco / (2 << ((r[0x10] >> 5) & 7)))
        return {"rf_hz": lo - self.if_hz, "lo_hz": lo, "bw_mhz": None, "calibrating": bool(r[0x05] & 0x20)}

    def read(self, n):
        self.reads[n] += 1
        return bytes(bitrev8(self.regs[i % len(self.regs)]) for i in range(n))


class R836(R820T):
    """Rafael Micro R836 / R840 / R850 DVB-T2/C silicon tuner (Opticum R265 Lite,
    Ariva 154/254 Combo): 49 registers, reference divider bit 2 of register 0x10,
    and supports both bit-reversed reads from register 0 and the A154/A254
    I2C_Read_Len [0xFB, reg] prefix."""
    NUM_REGS = 49
    REF_DIV_BIT = 0x04

    def __init__(self, xtal_hz=16_000_000, if_hz=5_000_000):
        super().__init__(xtal_hz=xtal_hz, if_hz=if_hz)
        self._fb_reg = None

    def write(self, data):
        if len(data) == 2 and data[0] == 0xFB:
            self._fb_reg = data[1]
            return True
        self._fb_reg = None
        return super().write(data)

    def read(self, n):
        if self._fb_reg is not None:
            reg, self._fb_reg = self._fb_reg, None
            self.reads[n] += 1
            return bytes(self.regs[(reg + i) % len(self.regs)] for i in range(n))
        return super().read(n)


class R840(R836):
    pass


class R850(R836):
    pass


class AV2011:
    """Airoha AV2011 DVB-S2 silicon tuner: a write sets the starting register
    (data[0]) and writes data[1:] sequentially from there; a 1-byte write
    selects the register to read next.  Register 0x0B bits 1..0 report PLL
    lock; a 4-register write to 0x00..0x03 programs the fractional-N divider
    (r[0] = round(rf_mhz / xtal_mhz), frac[16:0] in r[1]:r[2]:r[3][7])."""
    STATUS = {0x0B: 0x03}

    def __init__(self, xtal_hz=27_000_000):
        self.xtal_hz = xtal_hz
        self.regs = bytearray(64)
        self.read_reg = 0x0B
        self.reads = collections.Counter()
        self.writes = 0
        self.tuned = False

    def write(self, data):
        if data:
            self.read_reg = data[0] & 0x3F
            if data[0] == 0x00 and len(data) > 1:
                self.tuned = len(data) == 5
            for i, b in enumerate(data[1:]):
                reg = (data[0] + i) & 0x3F
                self.regs[reg] = b
                self.writes += 1
        return True

    def read(self, n):
        self.reads[self.read_reg] += 1
        out = [self.STATUS.get((self.read_reg + i) & 0x3F, self.regs[(self.read_reg + i) & 0x3F])
               for i in range(n)]
        return bytes(out)

    def frequency(self):
        """{"rf_hz", "bw_mhz"} of the L-band frequency tuned to, or None before
        the first 4-register PLL write."""
        if not self.tuned:
            return None
        r = self.regs
        frac = (r[1] << 9) | (r[2] << 1) | ((r[3] >> 7) & 1)
        nint = r[0] - (frac >> 16)
        rf_hz = round(self.xtal_hz * (nint + frac / (1 << 17)))
        bw_mhz = round(r[5] * 21.1 / 127) if r[5] else None
        return {"rf_hz": rf_hz, "bw_mhz": bw_mhz}


class Si2144:
    """Silicon Labs Si2144 DVB-T2/C silicon tuner (Strong SRT Prima VIII,
    0x802618A0..0x8026F76C): command/property protocol where every read starts
    with the status byte (0x80 CTS, 0xFE after RESET_HW, 0x89 CTS|DTVINT|TUNINT
    after TUNER_TUNE_FREQ)."""
    PART_INFO = bytes([0x01, 44, 0x32, 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00])
    GET_REV = bytes([0x32, 0x31, 0x32, 0x31, 0x01, 0x01, 0x00, 0x00, 0x02])

    def __init__(self):
        self.status = 0x80
        self.reply = b""
        self.last_cmd = 0
        self.props = {}
        self.rf_hz = None
        self.reads = collections.Counter()
        self.writes = 0

    def write(self, data):
        if not data:
            return True
        cmd = data[0]
        self.last_cmd = cmd
        self.writes += 1
        self.status = 0x80
        self.reply = b""
        if cmd == 0xC0 and len(data) >= 2 and data[1] == 0x05:      # RESET_HW -> pollForResetState expects 0xFE
            self.status = 0xFE
        elif cmd == 0x02:                                           # PART_INFO (part 44, romid 0x62)
            self.reply = self.PART_INFO
        elif cmd == 0x11:                                           # GET_REV
            self.reply = self.GET_REV
        elif cmd == 0x14 and len(data) >= 6:                        # SET_PROPERTY
            prop = int.from_bytes(data[2:4], "little")
            self.props[prop] = int.from_bytes(data[4:6], "little")
            self.reply = b"\x00"
        elif cmd == 0x15 and len(data) >= 4:                        # GET_PROPERTY
            prop = int.from_bytes(data[2:4], "little")
            self.reply = b"\x00" + self.props.get(prop, 0).to_bytes(2, "little")
        elif cmd == 0x41 and len(data) >= 8:                        # TUNER_TUNE_FREQ
            self.rf_hz = int.from_bytes(data[4:8], "little")
            self.status = 0x89
            self.reply = b"\x00"
        elif cmd == 0x42:                                           # TUNER_STATUS (tc=1, rssi=-50 dBm, dl=1)
            self.reply = bytes([0x01, 0x01, 0xCE]) + (self.rf_hz or 0).to_bytes(4, "little") + bytes([0x01, 0x00, 0x00, 0x00])
        return True

    def read(self, n):
        self.reads[self.last_cmd] += 1
        return (bytes([self.status]) + self.reply + bytes(n))[:n]

    def frequency(self):
        if not self.rf_hz:
            return None
        bw = (self.props[0x0703] & 0x0F) if 0x0703 in self.props else None
        return {"rf_hz": self.rf_hz, "bw_mhz": bw if bw in (6, 7, 8) else None}


class M3031:
    """ALi M3031 DVB-S2 silicon tuner at I2C 0x20 (Ferguson Ariva 104 / 204 /
    154 Combo / 254 Combo, 0x8029D010..0x8029DD68): a write sets the starting
    register (data[0]) and writes data[1:] sequentially; a 1-byte write selects
    the register to read next.  Register 0x00 is chip ID 2 (with 0x42 bit 6
    clear), 0x51 bit 0 is PLL lock, 0x74..0x75 is the 16-bit LE calibration
    word, and a 6-register write to 0x26..0x2B tunes the L-band synthesizer."""
    STATUS = {0x00: 0x02, 0x42: 0x00, 0x51: 0x01, 0x74: 0xEA, 0x75: 0x01}

    def __init__(self, xtal_hz=27_000_000):
        self.xtal_hz = xtal_hz
        self.regs = bytearray(256)
        self.read_reg = 0
        self.reads = collections.Counter()
        self.writes = 0
        self.tuned = False

    def write(self, data):
        if data:
            self.read_reg = data[0]
            if data[0] == 0x26 and len(data) >= 7:
                self.tuned = True
            for i, b in enumerate(data[1:]):
                reg = (data[0] + i) & 0xFF
                self.regs[reg] = b
                self.writes += 1
        return True

    def read(self, n):
        self.reads[self.read_reg] += 1
        return bytes(self.STATUS.get((self.read_reg + i) & 0xFF, self.regs[(self.read_reg + i) & 0xFF])
                     for i in range(n))

    def frequency(self):
        if not self.tuned:
            return None
        r = self.regs
        ref_div = r[0x27] or 4
        n_val = (r[0x29] << 8) | r[0x2A]
        out_div = 2 << (r[0x2B] & 3)
        rf_hz = round(self.xtal_hz * n_val / (ref_div * out_div))
        bw_mhz = round(r[0x2E] * 0.58) if r[0x2E] else None
        return {"rf_hz": rf_hz, "bw_mhz": bw_mhz}


class RDA5815:
    """RDA Microelectronics RDA5815 / RDA5815M DVB-S2 silicon tuner at I2C 0x60
    (Echosonic Mini ESR-250, 0x8027A2B4..0x8027AA00): a write sets the starting
    register (data[0]) and writes data[1:]; a 1-byte write selects the register
    to read next.  Register 0x00 is chip ID 0xC3 (bits 7..2 = 0xC0, rev 3),
    0x05 bit 1 is calibration done, 0x66 bit 7 is PLL lock, and writing
    registers 0x01..0x04 programs the 24-bit fractional-N word (rf_mhz * 2^17 /
    27 MHz in r[1]:r[2]:r[3])."""
    STATUS = {0x00: 0xC3, 0x05: 0x02, 0x66: 0x80}

    def __init__(self, xtal_hz=27_000_000):
        self.xtal_hz = xtal_hz
        self.regs = bytearray(256)
        self.read_reg = 0
        self.reads = collections.Counter()
        self.writes = 0
        self.tuned = False

    def write(self, data):
        if data:
            self.read_reg = data[0]
            for i, b in enumerate(data[1:]):
                reg = (data[0] + i) & 0xFF
                self.regs[reg] = b
                self.writes += 1
                if reg == 0x04 and (self.regs[1] or self.regs[2] or self.regs[3]):
                    self.tuned = True
        return True

    def read(self, n):
        self.reads[self.read_reg] += 1
        return bytes(self.STATUS.get((self.read_reg + i) & 0xFF, self.regs[(self.read_reg + i) & 0xFF])
                     for i in range(n))

    def frequency(self):
        if not self.tuned:
            return None
        r = self.regs
        n_val = (r[1] << 16) | (r[2] << 8) | r[3]
        rf_hz = round(self.xtal_hz * n_val / (1 << 17))
        return {"rf_hz": rf_hz, "bw_mhz": None}


MODELS = {
    "mxl603": MxL603,
    "mxl608": MxL608,
    "mxl5007t": MxL5007T,
    "mxl101sf": MxL101SF,
    "r820t": R820T,
    "r836": R836,
    "r840": R840,
    "r850": R850,
    "av2011": AV2011,
    "si2144": Si2144,
    "m3031": M3031,
    "rda5815": RDA5815,
}


def make(chip, **config):
    """A new model of `chip` (a key of MODELS, as in a sidecar's tunerModel);
    config: xtal_hz / if_hz where supported."""
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
    return isinstance(device, (MaxLinear, R820T, AV2011, Si2144, M3031, RDA5815))


