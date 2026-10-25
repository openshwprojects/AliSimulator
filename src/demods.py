"""
External demodulator chip models for the hardware I2C masters (i2c_scb.py):
what a firmware's NIM driver sees of the demodulator its board carries, so
that the driver's start-up finds the chip.  Which chip a board has, and at
which 7-bit address, is its dump sidecar's device.demodModel
(dump_catalog.py); loadFile puts that chip on the bus (sim.attach_demod).

  * AltoBeam ATBM7812 (the Ferguson Ariva T760i's DVB-T2 demodulator; the
    firmware's nim_atbm7812 driver): 16-bit register addresses -- a write is
    the address's high and low byte and the data for the registers from
    there on, a read returns the registers from the last address written.
    Register 0x0000 reads the chip ID 0xA8 (ATBM78xPowerOnInit compares it);
    the others read back what was written.  Without it the T760i's driver
    retried its power-on for ~125 M instructions ("u8ChipID:0") before its
    application went on.  It reports no lock: the application finds no
    signal (its tuner sits behind the demodulator's I2C gateway).
  * ALi S3501 (the DVB-S2 demodulator: the C3603's own -- the Opticum X110TS,
    chips/m3602.py puts it on the bus for that chip -- and the UNI S60's, an
    M3601S board): 7-bit address 0x33, a register file whose read-only
    registers 0xA3..0xA6 hold the chip ID the SDK's nim_s3501_get_type
    assembles from them, 0x350100C0 (NIM_CHIP_ID_M3501A).  Without it the
    S60's driver reset its tuner 11 times, logged "ERROR: reset nim
    failed!!!" and went on without a front end.  It never locks.
"""
from i2c_scb import RegisterSlave


class S3501(RegisterSlave):
    ADDRESS = 0x33
    ID = {0xA3: 0x01, 0xA4: 0x35, 0xA5: 0xC0, 0xA6: 0x00}
    # When locked (nim_s3503 / nim_s3501 drivers): CR04[5:0] = 0x3F (AGC, TR, CR,
    # Viterbi/LDPC, frame sync, MPEG lock), CR68[1:0] = 1 (DVB-S2), CR6B = 0x68
    # (map_type 3 = QPSK in bits 7:5, code_rate 4 = 3/4 in bits 4:1), CR28/29/73
    # SNR/AGC, CR6C..6E symbol rate 27500 kSym/s (0x006B6C).
    LOCK_REGS = {
        0x04: 0x3F,
        0x28: 0x80,
        0x29: 0x80,
        0x68: 0x01,
        0x6B: 0x68,
        0x6C: 0x6C,
        0x6D: 0x6B,
        0x6E: 0x00,
        0x73: 0x80,
    }

    def __init__(self, tuned=None):
        super().__init__(self.ID)
        self.signal = False
        self.tuned = tuned

    def locked(self):
        return self.signal and (self.tuned is None or self.tuned())

    def set_signal(self, on=True):
        self.signal = bool(on)

    def write(self, data):
        super().write(data)
        for reg, value in self.ID.items():
            self.regs[reg] = value
        return True

    def read(self, n):
        if not self.locked():
            return super().read(n)
        out = bytearray(n)
        for i in range(n):
            r = (self.address + i) % len(self.regs)
            if r in self.ID:
                out[i] = self.ID[r]
            elif r == 0x04:
                out[i] = 0x3F
            elif r == 0x68:
                out[i] = (self.regs[r] & 0xFC) | 0x01
            elif r == 0x6B:
                out[i] = 0x68
            elif r in self.LOCK_REGS:
                out[i] = self.regs[r] or self.LOCK_REGS[r]
            else:
                out[i] = self.regs[r]
        self.address = (self.address + n) % len(self.regs)
        return bytes(out)


class ATBM7812:
    CHIP_ID = {0x0000: 0xA8}
    # ATBMI2CTunerGateway(1) writes 0x01 to (0x01, 0x03) to open the I2C repeater
    # to the tuner behind the demodulator; ATBMI2CTunerGateway(0) writes 0x00.
    GATE_REG = 0x0103
    # ATBMGetLock (0x802200c4) and ATBMGetSysMode (0x80223c54):
    #   (0x00, 0x13) bit 0 = 0 (not in standby)
    #   (0x88, 0x6C) = 1 -> mode 3 (DVB-T2), (0x17, 0xEC) bit 0 = 1 (T2 FEC lock),
    #   (0x17, 0xB7) = 5, (0x0B, 0xDE) = 1
    #   (0x88, 0x6D) = 1 -> mode 2 (DVB-T),  (0x28, 0x2C) = 1, (0x95, 0x37) = 1
    #   (0x18, 0x2A) = 1 (ATBMFrameLock), (0x10, 0x28..0x29) AGC / signal level,
    #   (0x95, 0x20..0x21) SNR.
    LOCK_REGS = {
        0x0013: 0x00,
        0x002B: 0x00,
        0x0BDE: 0x01,
        0x1028: 0x80,
        0x1029: 0x02,
        0x17B7: 0x05,
        0x17EC: 0x01,
        0x182A: 0x01,
        0x282C: 0x01,
        0x886C: 0x01,
        0x9520: 0x20,
        0x9521: 0x01,
        0x9537: 0x01,
    }

    def __init__(self, tuned=None, tuner=None):
        self.regs = dict(self.CHIP_ID)
        self.address = 0
        self.signal = False
        self.tuned = tuned
        self.tuner = tuner              # optional downstream tuner behind the I2C gateway
        self.gate_changes = 0

    @property
    def gate_open(self):
        """Whether the I2C repeater gateway (register 0x0103 bit 0) is open."""
        return bool(self.regs.get(self.GATE_REG, 0) & 1)

    def locked(self):
        return self.signal and (self.tuned is None or self.tuned())

    def set_signal(self, on=True):
        self.signal = bool(on)

    def forward_write(self, data):
        """Forward an I2C write to the downstream tuner when the repeater gate is open."""
        if self.gate_open and self.tuner is not None:
            return self.tuner.write(data)
        return False

    def forward_read(self, n):
        """Forward an I2C read to the downstream tuner when the repeater gate is open."""
        if self.gate_open and self.tuner is not None:
            return self.tuner.read(n)
        return None

    def write(self, data):
        if len(data) >= 2:
            self.address = (data[0] << 8) | data[1]
            for i, b in enumerate(data[2:]):
                reg = (self.address + i) & 0xFFFF
                if reg == self.GATE_REG and (self.regs.get(reg, 0) & 1) != (b & 1):
                    self.gate_changes += 1
                if reg not in self.CHIP_ID:
                    self.regs[reg] = b
        return True

    def read(self, n):
        if not self.locked():
            return bytes(self.regs.get((self.address + i) & 0xFFFF, 0) for i in range(n))
        out = bytearray(n)
        for i in range(n):
            reg = (self.address + i) & 0xFFFF
            if reg in self.CHIP_ID:
                out[i] = self.CHIP_ID[reg]
            elif reg in self.LOCK_REGS:
                out[i] = self.LOCK_REGS[reg]
            else:
                out[i] = self.regs.get(reg, 0)
        return bytes(out)


MODELS = {"atbm7812": ATBM7812, "s3501": S3501}


def make(chip, **kwargs):
    """A new model of `chip` (a key of MODELS, as in a sidecar's demodModel)."""
    return MODELS[chip.lower()](**kwargs)

