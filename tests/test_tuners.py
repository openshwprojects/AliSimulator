"""
The tuner chip models (tuners.py) on the hardware I2C master model
(i2c_scb.py), driven register by register the way the firmwares' driver does
(dump.bin's application, 0x801B0A0C..): slave address at +4, bytes into the
FIFO at +0x10, the length at +C, a start at +0 (0x41 write, 0x45 read), the
result flags at +3 and the received bytes popped from +0x10.  Checks what
each chip answers: the MaxLinear lock registers through the 0xFB read prefix
(MxL603 0x2B, MxL5007T 0xD8), the R820T's bit-reversed status registers
read from register 0 (chip id 0x69, PLL lock bit 6 of register 2, a usable
filter calibration code in register 4), registers read back as written, and
no ACK from an address nobody models.  No firmware involved.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import i2c_scb
import tuners

BASE = 0x18200


class FakeUc:
    """The register window the master's read handler fills in."""
    def __init__(self):
        self.mem = bytearray(0x1000000)

    def mem_read(self, address, size):
        off = address & 0xFFFFFF
        return bytes(self.mem[off:off + size])

    def mem_write(self, address, data):
        off = address & 0xFFFFFF
        self.mem[off:off + len(data)] = data


class FakeSim:
    def __init__(self):
        self.i2c_devices = {}
        self.i2c_ack_all = False

    def _mmio_on(self, kind, handler, begin, end):
        pass

    def _device_access(self, uc):
        pass

    def log(self, msg):
        pass


sim, uc = FakeSim(), FakeUc()
master = i2c_scb.I2cMaster(sim, BASE, "SCB0")


def wr(off, value):
    master._write(uc, 17, 0xB8000000 + BASE + off, 1, value, None)


def rd(off):
    master._read(uc, 16, 0xB8000000 + BASE + off, 1, 0, None)
    return uc.mem[BASE + off]


def i2c_write(addr7, data):
    wr(0x0C, 0x00)                      # FIFO reset
    wr(0x03, 0x0F)
    wr(0x04, addr7 << 1)
    for b in data:
        wr(0x10, b)
    wr(0x0C, 0x80 | len(data))
    wr(0x00, 0x41)
    return rd(0x03) & 0x0F == 0x01      # complete, no error = ACK


def i2c_read(addr7, n):
    wr(0x0C, 0x00)
    wr(0x03, 0x0F)
    wr(0x04, (addr7 << 1) | 1)
    wr(0x0C, 0x80 | n)
    wr(0x00, 0x45)
    if rd(0x03) & 0x0F != 0x01:
        return None
    return bytes(rd(0x10) for _ in range(n))


ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


print("=== Test: tuner chip models on the I2C master model ===")

# no device: no ACK (the driver reports -9 at once instead of timing out)
check(not i2c_write(0x60, [0x0B, 0x01]), "an address nobody models gets no ACK")

# MxL603 family: (register, value) pairs, 0xFB selects the register to read
mxl = sim.i2c_devices[0x60] = tuners.make("mxl603")
check(i2c_write(0x60, [0xFF, 0x00]) and i2c_write(0x60, [0x14, 0x13]), "MxL603: register writes are acknowledged")
i2c_write(0x60, [0xFB, 0x14])
check(i2c_read(0x60, 1) == b"\x13", "MxL603: a register reads back as written (0xFB prefix)")
i2c_write(0x60, [0xFB, 0x2B])
check(i2c_read(0x60, 1)[0] & 0x03 == 0x03, "MxL603: register 0x2B reports RF and reference lock")
check(mxl.reads[0x2B] == 1, "MxL603: the model counts the lock-status reads")

# MxL5007T: several pairs in one write, lock in 0xD8
sim.i2c_devices[0x60] = tuners.make("mxl5007t")
check(i2c_write(0x60, [0x02, 0x03, 0x03, 0x48, 0x05, 0x04]), "MxL5007T: a write of three pairs is acknowledged")
i2c_write(0x60, [0xFB, 0x03])
check(i2c_read(0x60, 1) == b"\x48", "MxL5007T: the second pair of a write landed")
i2c_write(0x60, [0xFB, 0xD8])
check(i2c_read(0x60, 1)[0] & 0x0F == 0x0F, "MxL5007T: register 0xD8 reports RF and reference lock")

# R820T at 0x1A: reads start at register 0, every byte bit-reversed
r820t = sim.i2c_devices[0x1A] = tuners.make("r820t")
check(i2c_write(0x1A, [0x05, 0x83, 0x32, 0x75]), "R820T: a write from register 5 on is acknowledged")
raw = i2c_read(0x1A, 5)
regs = bytes(tuners.bitrev8(b) for b in raw)
check(regs[0] == 0x69, f"R820T: register 0 is the chip id 0x69 (read {regs[0]:#04x}, on the wire {raw[0]:#04x})")
check(regs[2] & 0x40, "R820T: register 2 bit 6 reports the PLL locked")
check(regs[4] & 0x0F not in (0x00, 0x0F), "R820T: register 4 holds a usable filter calibration code")
check(r820t.regs[5:8] == bytes([0x83, 0x32, 0x75]), "R820T: the written registers hold their values")
i2c_write(0x1A, [0x00, 0xFF])
check(r820t.regs[0] == 0x69, "R820T: a write cannot change the status registers 0..4")
check(r820t.reads[5] == 1, "R820T: the model counts reads by length")
check(all(tuners.is_tuner(tuners.make(c)) for c in tuners.MODELS) and not tuners.is_tuner(i2c_scb.AckAll()),
      "is_tuner() recognises every model and nothing else")

# the frequency each driver tuned to, from the register writes the firmwares made (dump sidecars)
m = tuners.make("mxl603")
check(m.frequency() is None and tuners.describe(m) == "MxL603: not tuned", "MxL603: no frequency before a tune")
m.write(bytes([0x0F, 0x22, 0x10, 0x80, 0x11, 0x76]))           # Cabletech URZ0194S: UHF channel 21, 8 MHz
check(tuners.describe(m) == "MxL603: 474.000 MHz / 8 MHz", f"MxL603: 0x7680 / 64 -> {tuners.describe(m)}")
m = tuners.make("mxl5007t")
m.write(bytes([0x0F, 0x00, 0x0C, 0x3F, 0x0D, 0x80]))           # URZ0195 (2012): its tune sequence
m.write(bytes([0x0E, 0x8E, 0x1F, 0x87, 0x20, 0x1F]))
check(tuners.describe(m) == "MxL5007T: 570.000 MHz / 8 MHz", f"MxL5007T: 0x8E80 / 64 -> {tuners.describe(m)}")
r = tuners.make("r820t", xtal_hz=16_000_000, if_hz=4_570_000)
check(r.frequency() is None, "R820T: no frequency before the driver programs the PLL")
r.write(bytes([0x05, 0xA3]))                                   # Globo N3: image-rejection calibration, input off
r.write(bytes([0x10, 0x24]))
r.write(bytes([0x14, 0x4D]))
r.write(bytes([0x12, 0x88]))                                   # SDM off
check(tuners.describe(r) == "R820T: calibrating (LO 528.000 MHz)", f"R820T: the first ring point -> {tuners.describe(r)}")
r.write(bytes([0x05, 0x03]))                                   # the channel: input on, then its PLL
r.write(bytes([0x10, 0x64]))
r.write(bytes([0x14, 0x16]))
r.write(bytes([0x12, 0x80]))
r.write(bytes([0x16, 0x88]))
r.write(bytes([0x15, 0xFC]))
f = r.frequency()
check(abs(f["rf_hz"] - 198_500_000) < 1_000 and abs(f["lo_hz"] - 203_070_000) < 1_000,
      f"R820T: N 101, SDM 0x88FC, divider 16 -> {tuners.describe(r)} (VHF channel 8)")

print(f"\n[{'PASS' if ok else 'FAIL'}] tuner models")
sys.exit(0 if ok else 1)
