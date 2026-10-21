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
no ACK from an address nobody models.  And the external demodulator model
(demods.py): the ATBM7812's 16-bit register addresses and its read-only chip
ID 0xA8 in register 0.  No firmware involved.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import demods
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

# ATBM7812 at 0x40 (the T760i's demodulator): 16-bit register addresses, the chip ID in register 0
atbm = sim.i2c_devices[0x40] = demods.make("atbm7812")
check(i2c_write(0x40, [0x00, 0x00]) and i2c_read(0x40, 1) == b"\xA8",
      "ATBM7812: register 0x0000 reads the chip ID 0xA8 (ATBM78xPowerOnInit's check)")
check(i2c_write(0x40, [0x0A, 0x00, 0x55, 0x66]) and i2c_write(0x40, [0x0A, 0x01]) and i2c_read(0x40, 1) == b"\x66",
      "ATBM7812: a write from register 0x0A00 on lands in 0x0A00 / 0x0A01")
i2c_write(0x40, [0x00, 0x00, 0x12])
check(atbm.regs[0x0000] == 0xA8, "ATBM7812: a write cannot change the chip ID")

# AV2011 at 0x63 (the Opticum X110p 1.0.11C's DVB-S2 tuner): sequential writes, lock in 0x0B
av = sim.i2c_devices[0x63] = tuners.make("av2011")
check(av.frequency() is None and i2c_write(0x63, [0x00, 0x38, 0x00]) and av.frequency() is None,
      "AV2011: the X110p's 2-register startup check [0x00, 0x38, 0x00] is acknowledged and does not count as a tune")
check(i2c_write(0x63, [0x0B]) and i2c_read(0x63, 1) == b"\x03",
      "AV2011: register 0x0B reports PLL lock (0x03)")
i2c_write(0x63, [0x05, 0xA3])
i2c_write(0x63, [0x00, 56, 0x00, 0x00, 0x50])                   # 56 * 27 MHz = 1512.000 MHz
check(tuners.describe(av) == "AV2011: 1512.000 MHz / 27 MHz",
      f"AV2011: r[0]=56, frac=0, r[5]=0xA3 -> {tuners.describe(av)}")

# MxL608 at 0x60 (Opticum Blue R265 Lite) and MxL5007T version register 0xD3 (URZ0083 / KM0183 / Ariva T50)
m608 = sim.i2c_devices[0x60] = tuners.make("mxl608")
i2c_write(0x60, [0xFB, 0x2B])
check(i2c_read(0x60, 1) == b"\x03", "MxL608: register 0x2B reports RF and reference lock")
m5007 = sim.i2c_devices[0x63] = tuners.make("mxl5007t")
i2c_write(0x63, [0xFB, 0xD3])
check(i2c_read(0x63, 1) == b"\x14", "MxL5007T: register 0xD3 reports MxL_5007T_V4 (0x14)")

# MxL101SF at 0x60 (URZ0086 / KM0186 / THT501): chip ID 0x61 in 0xFC, lock in 0x26:0x25 / 0x28 / 0x2A, tune in 0x1F:0x1E
m101 = sim.i2c_devices[0x60] = tuners.make("mxl101sf")
i2c_write(0x60, [0xFB, 0xFC])
check(i2c_read(0x60, 1) == b"\x61", "MxL101SF: register 0xFC reports chip ID 0x61")
i2c_write(0x60, [0x1D, 0x3F, 0x1E, 0x80, 0x1F, 0x76])
check(tuners.describe(m101) == "MxL101SF: 474.000 MHz / 8 MHz", f"MxL101SF: 0x7680 / 64 -> {tuners.describe(m101)}")

# R836 / R840 / R850 at 0x3A (Ariva 154/254 Combo): 49 registers, 0xFB read prefix + bit-reversed status reads
r836 = sim.i2c_devices[0x3A] = tuners.make("r836")
check(len(r836.regs) == 49 and isinstance(tuners.make("r840"), tuners.R836) and isinstance(tuners.make("r850"), tuners.R836),
      "R836 / R840 / R850: 49-register Rafael Micro family")
i2c_write(0x3A, [0xFB, 0x00])
check(i2c_read(0x3A, 3) == bytes([0x69, 0x20, 0x40]), "R836: [0xFB, reg] prefix reads unreversed registers")
check(tuners.bitrev8(i2c_read(0x3A, 1)[0]) == 0x69, "R836: standard read without 0xFB prefix stays bit-reversed")

# Si2144 at 0x60 (Strong SRT Prima VIII): RESET_HW -> 0xFE, PART_INFO -> part 44 / romid 0x62, TUNER_TUNE_FREQ
si = sim.i2c_devices[0x60] = tuners.make("si2144")
i2c_write(0x60, [0xC0, 0x05, 0x00])
check(i2c_read(0x60, 1) == b"\xFE", "Si2144: RESET_HW sets status byte to 0xFE for pollForResetState")
i2c_write(0x60, [0x02])
part = i2c_read(0x60, 14)
check(part[0] == 0x80 and part[2] == 44 and part[12] == 0x62, "Si2144: PART_INFO reports part 44 and romid 0x62")
i2c_write(0x60, [0x14, 0x00, 0x03, 0x07, 0x08, 0x00])           # DTV_MODE (0x0703) = 8 MHz
i2c_write(0x60, [0x41, 0x00, 0x00, 0x00] + list((474_000_000).to_bytes(4, "little")))
check(i2c_read(0x60, 1) == b"\x89" and tuners.describe(si) == "Si2144: 474.000 MHz / 8 MHz",
      f"Si2144: TUNER_TUNE_FREQ -> {tuners.describe(si)}")

# M3031 at 0x20 (Ferguson Ariva 104 / 204 / 154 / 254): chip ID 2 in 0x00, lock in 0x51, tune in 0x26..0x2B
m3031 = sim.i2c_devices[0x20] = tuners.make("m3031")
check(i2c_write(0x20, [0x00]) and i2c_read(0x20, 1) == b"\x02" and i2c_write(0x20, [0x51]) and i2c_read(0x20, 1) == b"\x01",
      "M3031: register 0x00 reports chip ID 2 and register 0x51 reports PLL lock")
i2c_write(0x20, [0x26, 0x00, 4, 0x00, 0x01, 0xC0, 0x00])        # N=448, ref_div=4, out_div=2 -> 27 * 448 / 8 = 1512 MHz
check(tuners.describe(m3031) == "M3031: 1512.000 MHz", f"M3031: 0x26..0x2B PLL write -> {tuners.describe(m3031)}")

# RDA5815 at 0x60 (Echosonic Mini ESR-250): chip ID 0xC3 in 0x00, calibration 0x02 in 0x05, lock 0x80 in 0x66, tune in 0x01..0x04
rda = sim.i2c_devices[0x60] = tuners.make("rda5815")
check(i2c_write(0x60, [0x00]) and i2c_read(0x60, 1) == b"\xC3" and i2c_write(0x60, [0x66]) and i2c_read(0x60, 1) == b"\x80",
      "RDA5815: register 0x00 reports chip ID 0xC3 and register 0x66 reports PLL lock")
i2c_write(0x60, [0x01, 0x70, 0x00, 0x00, 0x00])                 # n = 0x700000 -> 27 * 56 = 1512 MHz
check(tuners.describe(rda) == "RDA5815: 1512.000 MHz", f"RDA5815: 0x01..0x04 PLL write -> {tuners.describe(rda)}")

print(f"\n[{'PASS' if ok else 'FAIL'}] tuner models")
sys.exit(0 if ok else 1)


