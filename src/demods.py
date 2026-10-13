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
"""


class ATBM7812:
    CHIP_ID = {0x0000: 0xA8}

    def __init__(self):
        self.regs = dict(self.CHIP_ID)
        self.address = 0

    def write(self, data):
        if len(data) >= 2:
            self.address = (data[0] << 8) | data[1]
            for i, b in enumerate(data[2:]):
                reg = (self.address + i) & 0xFFFF
                if reg not in self.CHIP_ID:
                    self.regs[reg] = b
        return True

    def read(self, n):
        return bytes(self.regs.get((self.address + i) & 0xFFFF, 0) for i in range(n))


MODELS = {"atbm7812": ATBM7812}


def make(chip):
    """A new model of `chip` (a key of MODELS, as in a sidecar's demodModel)."""
    return MODELS[chip.lower()]()
