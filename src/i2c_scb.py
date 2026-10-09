"""
The ALi SoCs' hardware I2C masters ("SCB": 0xB8018200 and 0xB8018700 on the
M3801, 0xB8018B00 on the M3821; the tuner, an EEPROM and other board chips
hang on them), as the firmware's driver uses them (dump.bin's application,
0x801B0A0C..0x801B14EC; the M3821 application is a "newer chip" to it and
writes +0x23 / +0x24):

  +0     control: bit 7 enable; a write with bit 0 set starts a transfer --
         0x41 a write of the FIFO's bytes, 0x45 a read, 0x49 a write of the
         sub-address at +5 (and +0x25.. on newer chips, +0x24 = how many more)
         followed by a read
  +1     status, cleared by writing 0: bits 7..5 = a transfer in progress (the
         driver waits for them to clear after a start, checking +3 for an error
         meanwhile, and for bit 5 to be clear before one), bit 1 = FIFO full;
         the model's transfers complete at once, so they always read clear
  +2     bits 3..0 cleared at init; +3 written 0x0F before a transfer and
         polled after it: bit 0 = complete, bits 3..1 = error -- the driver
         reads +3 & 0x0E as "no ACK" (-9), a +1 that never shows done as a
         timeout (-34) after 99 ms
  +4     the slave address byte (bit 0 = read), +5 the first data byte again
  +6..+B clock dividers (6 MHz / SCL), +0x14 bits 2..0 read 0 = bus idle
  +C     bit 7 FIFO enable | the transfer length (bits 4..0; bits 7..5 at
         +0x23 on newer chips), reading back as the number of received bytes
         waiting in the FIFO
  +0x10  the data FIFO: writes queue the bytes to send, reads pop received ones

A transfer completes the moment it is started.  The slaves are
sim.i2c_devices, {7-bit address: device} with device.write(data) -> bool (the
ACK) and device.read(n) -> bytes or None (no ACK); an address nobody answers
gets no ACK (the driver's -9) -- unless sim.i2c_ack_all is set, when every
address answers and reads return zeros, so a tuner driver runs its whole
register initialisation, which the log shows, with no model of the tuner.
RegisterSlave is the usual chip: a register file addressed by the first byte
written, auto-incrementing, read back from the address last written.
"""
import collections


class RegisterSlave:
    """A chip with 8-bit registers: a write sets the address (its first byte)
    and the data after it, a read returns registers from that address on."""
    def __init__(self, registers=None, size=256, fill=0x00):
        self.regs = bytearray([fill]) * size
        for address, value in (registers or {}).items():
            self.regs[address] = value
        self.address = 0

    def write(self, data):
        if data:
            self.address = data[0]
            for i, b in enumerate(data[1:]):
                self.regs[(self.address + i) % len(self.regs)] = b
        return True

    def read(self, n):
        out = bytes(self.regs[(self.address + i) % len(self.regs)] for i in range(n))
        self.address = (self.address + n) % len(self.regs)
        return out


class AckAll:
    """Answers at any address: writes acknowledged, reads give zeros."""
    def write(self, data):
        return True

    def read(self, n):
        return bytes(n)


class I2cMaster:
    """One SCB block; the simulator makes one per base in its I2C_SCB_BASES."""
    SIZE = 0x28
    LOG_FIRST, LOG_EVERY = 64, 256          # transactions logged: the first ones, then one in N

    def __init__(self, sim, base, name):
        self.sim, self.base, self.name = sim, base, name
        self.transactions = 0
        self.reset()
        sim._mmio_on('w', self._write, base, base + self.SIZE - 1)
        sim._mmio_on('r', self._read, base, base + self.SIZE - 1)

    def reset(self):
        self.tx = bytearray()               # queued for the next write
        self.rx = collections.deque()       # received, popped at +0x10
        self.status = 0                     # +1
        self.flags = 0                      # +3
        self.slave = 0                      # +4
        self.sub = bytearray(4)             # +5, +0x25..+0x27
        self.sub_extra = 0                  # +0x24
        self.length = 0                     # +C bits 4..0 | +0x23 << 5
        self.length_hi = 0

    def _write(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        for i in range(size):
            b, o = (value >> (8 * i)) & 0xFF, off + i
            if o == 0x00 and b & 0x01:
                self._transfer(b)
            elif o == 0x01:
                self.status = 0 if b == 0 else self.status & ~b
            elif o == 0x03:
                self.flags &= ~b
            elif o == 0x04:
                self.slave = b
            elif o == 0x05:
                self.sub[0] = b
            elif o == 0x0C:
                self.length = b & 0x1F
                if not b & 0x80:
                    self.tx.clear()
                    self.rx.clear()
            elif o == 0x10:
                self.tx.append(b)
            elif o == 0x23:
                self.length_hi = b
            elif o == 0x24:
                self.sub_extra = b & 3
            elif 0x25 <= o <= 0x27:
                self.sub[o - 0x24] = b

    def _read(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        out = bytearray(uc.mem_read(address, size))
        for i in range(size):
            o = off + i
            if o == 0x01:
                out[i] = self.status
            elif o == 0x03:
                out[i] = self.flags
            elif o == 0x0C:
                out[i] = 0x80 | min(len(self.rx), 0x1F)
            elif o == 0x10:
                out[i] = self.rx.popleft() if self.rx else 0xFF
            elif o == 0x14:
                out[i] = 0
        uc.mem_write(address, bytes(out))

    def _transfer(self, control):
        sim = self.sim
        read, combined = bool(control & 0x04), bool(control & 0x08)
        addr7 = self.slave >> 1
        n = self.length | (self.length_hi << 5)
        device = sim.i2c_devices.get(addr7) or (AckAll() if sim.i2c_ack_all else None)
        sent, got, ack = b"", b"", False
        if combined:
            sent = bytes(self.sub[:1 + self.sub_extra])
            ack = bool(device) and device.write(sent)
            if ack:
                got = device.read(n)
                ack = got is not None
        elif read:
            got = device.read(n) if device else None
            ack = got is not None
        else:
            sent = bytes(self.tx)
            ack = bool(device) and device.write(sent)
        self.tx.clear()
        if ack and (read or combined):
            got = (got or b"")[:n] + bytes(max(0, n - len(got or b"")))
            self.rx.extend(got)
        self.flags = 0x01 if ack else 0x02          # (+1 stays clear: the transfer is over)
        self.transactions += 1
        if self.transactions <= self.LOG_FIRST or self.transactions % self.LOG_EVERY == 0:
            what = "W" if not (read or combined) else ("WR" if combined else "R")
            sim.log(f"[I2C] {self.name} {what} 0x{addr7:02X}" + ("" if ack else " (no ACK)")
                    + (": " + sent.hex(" ") if sent else "") + (f" -> {bytes(got).hex(' ')}" if got else ""))
