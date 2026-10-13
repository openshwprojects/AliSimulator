"""
Fast check of the bit-banged I2C bus model (gpio_i2c.py), no firmware:

A Python copy of an open-drain bit-bang driver (DO kept 0, a line pulled low
by making it an output, released by making it an input -- the Cabletech
URZ0086's application drives its tuner's bus, SCL = GPIO 44, SDA = GPIO 43,
this way) talks to a MaxLinear tuner model through the bus: it writes
registers, selects one with the 0xFB prefix and reads it back, and an address
nobody answers gets no acknowledge.  The CPU side reports pin levels as the
simulator does (simulator._hook_gpio_write) and reads the pins through the
bus's di_override (simulator._hook_gpio_di_read).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import tuners
from gpio_i2c import GpioI2cBus

SCL, SDA = 44, 43                       # bank 1 (DO 0x0D4, DI 0x0D0)
DO, DI = 0x0D4, 0x0D0


class Sim:
    """What the bus uses of the simulator: the I2C slaves and the log."""
    def __init__(self):
        self.i2c_devices = {}
        self.i2c_ack_all = False
        self.lines = []

    def log(self, msg):
        self.lines.append(msg)


class OpenDrainMaster:
    def __init__(self, bus):
        self.bus, self.dir = bus, 0
        self.notify()

    def notify(self):
        self.bus.on_gpio_write(0xB8000000 + DO, 4, ~self.dir & 0xFFFFFFFF)

    def set(self, scl=None, sda=None):
        for pin, level in ((SCL - 32, scl), (SDA - 32, sda)):
            if level is not None:
                self.dir = self.dir & ~(1 << pin) if level else self.dir | (1 << pin)
        self.notify()

    def read_sda(self):
        di = self.bus.di_override(DI, 0) & ~self.dir
        return (di >> (SDA - 32)) & 1

    def start(self):
        self.set(scl=1, sda=1); self.set(sda=0); self.set(scl=0)

    def stop(self):
        self.set(sda=0); self.set(scl=1); self.set(sda=1)

    def write_byte(self, b):
        for i in range(7, -1, -1):
            self.set(sda=(b >> i) & 1); self.set(scl=1); self.set(scl=0)
        self.set(sda=1); self.set(scl=1); ack = self.read_sda() == 0; self.set(scl=0)
        return ack

    def read_byte(self, last):
        self.set(sda=1)
        v = 0
        for _ in range(8):
            self.set(scl=1); v = (v << 1) | self.read_sda(); self.set(scl=0)
        self.set(sda=1 if last else 0); self.set(scl=1); self.set(scl=0); self.set(sda=1)
        return v

    def write(self, addr7, data):
        self.start()
        ok = self.write_byte(addr7 << 1) and all(self.write_byte(b) for b in data)
        self.stop()
        return ok

    def read(self, addr7, n):
        self.start()
        if not self.write_byte((addr7 << 1) | 1):
            self.stop()
            return None
        got = [self.read_byte(i == n - 1) for i in range(n)]
        self.stop()
        return got


def main():
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    sim = Sim()
    bus = GpioI2cBus(sim, SCL, SDA)
    cpu = OpenDrainMaster(bus)
    tuner = tuners.make("mxl5007t")
    sim.i2c_devices[0x60] = tuner
    check(cpu.read_sda() == 1, "the idle bus reads high")
    check(cpu.write(0x60, [0x02, 0x01, 0x03, 0x5A]), "a register write to the tuner at 0x60 is acknowledged")
    check(tuner.regs[0x02] == 0x01 and tuner.regs[0x03] == 0x5A, "the tuner model got the registers")
    check(cpu.write(0x60, [0xFB, 0x03]), "the 0xFB read prefix selects register 0x03")
    got = cpu.read(0x60, 1)
    check(got == [0x5A], f"a one-byte read returns it ({got})")
    check(not cpu.write(0x61, [0x00]), "an address nobody answers is not acknowledged")
    check(cpu.read(0x61, 1) is None, "nor is a read from it")
    check(bus.state == 'IDLE' and cpu.read_sda() == 1, "the bus is idle and high again")
    sim.i2c_ack_all = True
    check(cpu.read(0x61, 2) == [0, 0], "with i2c_ack_all every address answers with zeros")
    check(any("W 0x60: 02 01 03 5a" in line for line in sim.lines), "the transfers are logged")
    print("[PASS] GPIO I2C bus" if ok else "[FAIL] GPIO I2C bus")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
