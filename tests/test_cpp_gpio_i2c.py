"""
The bit-banged I2C bus in the C++ core (Core::gi2c_*, simulator_cpp
_cpp_gpio_sync), no firmware: a guest program bit-bangs a MaxLinear tuner
model's bus open-drain (DO kept 0, a line pulled low by making it an output,
released by making it an input -- as the Cabletech URZ0086's application does
on SCL = GPIO 44, SDA = GPIO 43) with plain stores to the bank's DIR register,
and records every read of the bank's DI register in RAM.  The same pin
sequence goes through the Python model (gpio_i2c.GpioI2cBus, the Unicorn
engine's) and through the simulator with the bus left in Python
(ALISIM_CPP_GPIO_I2C=0): every DI read must agree, the tuner must get its
registers and answer the read back, an address nobody answers must get no
acknowledge, and i2c_ack_all must answer with zeros.  The GPIO log handed to
Python must carry only the panel's pins (gpio_watch), not the bus's edges.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
from engine_check import CPP, not_applicable

if not CPP:
    not_applicable("the bit-banged I2C bus in the C++ core")

from unicorn.mips_const import UC_MIPS_REG_PC

import tuners
from gpio_i2c import GpioI2cBus
from simulator import AliMipsSimulator
from tm1650_decoder import TM1650Decoder

SCL, SDA = 44, 43                       # bank 1: DI 0x0D0, DO 0x0D4, DIR 0x0D8
SCL_BIT, SDA_BIT = SCL - 32, SDA - 32
DI, DO, DIR = 0x0D0, 0x0D4, 0x0D8
CODE, RECORDS = 0x80001000, 0xA0040000
T0, T1, S0, S1 = 8, 9, 16, 17


class Driver:
    """The open-drain driver of test_gpio_i2c.py, as a list of operations:
    ("w", DIR value) a store, ("r", k) the k-th DI read."""
    def __init__(self):
        self.dir, self.ops, self.reads = 0, [], 0

    def set(self, scl=None, sda=None):
        for bit, level in ((SCL_BIT, scl), (SDA_BIT, sda)):
            if level is not None:
                self.dir = self.dir & ~(1 << bit) if level else self.dir | (1 << bit)
        self.ops.append(("w", self.dir))

    def read(self):
        self.ops.append(("r", self.reads))
        self.reads += 1
        return self.reads - 1

    def start(self):
        self.set(scl=1, sda=1); self.set(sda=0); self.set(scl=0)

    def stop(self):
        self.set(sda=0); self.set(scl=1); self.set(sda=1)

    def write_byte(self, b):
        for i in range(7, -1, -1):
            self.set(sda=(b >> i) & 1); self.set(scl=1); self.set(scl=0)
        self.set(sda=1); self.set(scl=1); ack = self.read(); self.set(scl=0)
        return ack

    def read_byte(self, last):
        self.set(sda=1)
        bits = []
        for _ in range(8):
            self.set(scl=1); bits.append(self.read()); self.set(scl=0)
        self.set(sda=1 if last else 0); self.set(scl=1); self.set(scl=0); self.set(sda=1)
        return bits

    def write(self, addr7, data):
        self.start()
        acks = [self.write_byte(addr7 << 1)] + [self.write_byte(b) for b in data]
        self.stop()
        return acks

    def read_tx(self, addr7, n):
        self.start()
        ack = self.write_byte((addr7 << 1) | 1)
        got = [self.read_byte(i == n - 1) for i in range(n)]
        self.stop()
        return ack, got


def program(ops):
    """The guest code for the operations: stores to DIR, DI loads kept at RECORDS."""
    w = [0x3C000000 | S0 << 16 | 0xB800,                        # lui s0, 0xB800
         0x3C000000 | S1 << 16 | (RECORDS >> 16)]               # lui s1, RECORDS >> 16
    for op, v in ops:
        if op == "w":
            w += [0x3C000000 | T0 << 16 | (v >> 16), 0x34000000 | T0 << 21 | T0 << 16 | (v & 0xFFFF),
                  0xAC000000 | S0 << 21 | T0 << 16 | DIR]       # lui / ori t0; sw t0, DIR(s0)
        else:
            w += [0x8C000000 | S0 << 21 | T1 << 16 | DI,        # lw t1, DI(s0)
                  0xAC000000 | S1 << 21 | T1 << 16 | (4 * v)]   # sw t1, 4k(s1)
    w += [0x1000FFFF, 0]                                        # b . ; nop
    return struct.pack(f"<{len(w)}I", *w), CODE + 4 * (len(w) - 2)


class Log:
    def __init__(self):
        self.lines = []

    def __call__(self, msg):
        self.lines.append(msg)


def run_sim(native, phases):
    """The phases (operations, ack_all) on a simulator with the bus in the core
    (native) or in Python: the DI reads, the tuner, the bus, the panel's events."""
    os.environ["ALISIM_CPP_GPIO_I2C"] = "1" if native else "0"
    log = Log()
    sim = AliMipsSimulator(engine="cpp", log_handler=log)
    tuner = tuners.make("mxl5007t")
    sim.i2c_devices[0x60] = tuner
    bus = GpioI2cBus(sim, SCL, SDA)
    sim.gpio_devices = [bus]
    panel = TM1650Decoder(scl_gpio=SCL + 2, sda_gpio=SDA - 2, log_handler=lambda m: None)   # (other pins, same bank)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    reads = []
    for ops, ack_all in phases:
        sim.i2c_ack_all = ack_all
        code, end = program(ops)
        sim.mu.mem_write(CODE, code)
        sim.mu.mem_write(RECORDS, b"\0" * 4 * max(1, sum(1 for op, _ in ops if op == "r")))
        sim.mu.reg_write(UC_MIPS_REG_PC, CODE)
        for _ in range(200):
            sim.run(max_instructions=sim.instruction_count + 2000)
            if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == end:
                break
        n = sum(1 for op, _ in ops if op == "r")
        reads.append(list(struct.unpack(f"<{n}I", bytes(sim.mu.mem_read(RECORDS, 4 * n)))) if n else [])
    return sim, bus, tuner, reads, log, panel


def main():
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    d1 = Driver()
    w1 = d1.write(0x60, [0x02, 0x01, 0x03, 0x5A])
    w2 = d1.write(0x60, [0xFB, 0x03])
    r_ack, r_bits = d1.read_tx(0x60, 1)
    n_ack = d1.write(0x61, [0x00])
    nr_ack, _ = d1.read_tx(0x61, 1)
    d2 = Driver()
    a_ack, a_bits = d2.read_tx(0x61, 2)
    phases = [(d1.ops, False), (d2.ops, True)]

    def sda(v):
        return (v >> SDA_BIT) & 1

    sim, bus, tuner, reads, log, panel = run_sim(True, phases)
    r1, r2 = reads
    check(bus.native is not None and sim._gi2c_bus is bus, "the bus runs in the core")
    check(all(sda(r1[k]) == 0 for k in w1), "a register write to the tuner at 0x60 is acknowledged")
    check(tuner.regs[0x02] == 0x01 and tuner.regs[0x03] == 0x5A, "the tuner model got the registers")
    check(all(sda(r1[k]) == 0 for k in w2), "the 0xFB read prefix is acknowledged")
    got = sum(sda(r1[k]) << (7 - i) for i, k in enumerate(r_bits[0]))
    check(sda(r1[r_ack]) == 0 and got == 0x5A, f"a one-byte read returns register 0x03 (0x{got:02X})")
    check(sda(r1[n_ack[0]]) == 1 and sda(r1[nr_ack]) == 1, "an address nobody answers is not acknowledged")
    zeros = [sum(sda(r2[k]) << (7 - i) for i, k in enumerate(bits)) for bits in a_bits]
    check(sda(r2[a_ack]) == 0 and zeros == [0, 0], f"with i2c_ack_all every address answers with zeros ({zeros})")
    check(bus.native(1) == 0 and bus.native(0) == -1, "the bus is idle and released at the end")
    check(any("W 0x60: 02 01 03 5a" in line for line in log.lines), "the transfers are logged")
    edges = bus.native(4)
    check(edges > 100, f"the core followed the bus's edges ({edges})")
    check(panel.gpio_event_count <= 1,
          f"the panel (other pins of the bank) was handed no bus edges ({panel.gpio_event_count} events)")

    # the same pins with the bus left in Python: the same reads, bit for bit
    _sim0, bus0, tuner0, reads0, _log0, panel0 = run_sim(False, phases)
    check(bus0.native is None, "ALISIM_CPP_GPIO_I2C=0 leaves the bus in Python")
    check(reads0 == reads, "every DI read is the same with the bus in Python")
    check(tuner0.regs == tuner.regs, "and so are the tuner's registers")
    check(panel0.gpio_event_count > 100, f"(there the bank's every store goes to Python: {panel0.gpio_event_count})")
    os.environ.pop("ALISIM_CPP_GPIO_I2C", None)
    print("[PASS] GPIO I2C bus in the C++ core" if ok else "[FAIL] GPIO I2C bus in the C++ core")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
