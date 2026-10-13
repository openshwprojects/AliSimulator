"""
I2C buses a firmware bit-bangs over two GPIO pins (the SDK's i2c_gpio
driver) to board chips the simulator models: the Cabletech URZ0086's tuner,
a MaxLinear at 0x60, hangs on SCL = GPIO 44, SDA = GPIO 43, which its
application drives open-drain.  The slaves are the hardware masters'
(i2c_scb.py, sim.i2c_devices: device.write(data) -> ACK, device.read(n) ->
bytes or None), so a tuner model attached with sim.attach_tuner() answers on
either kind of bus.

The model follows the pin levels the simulator reports for every write of a
bank's DO or DIR register (on_gpio_write, as the panel decoders get them) and
answers the firmware's reads of the pins (di_override): SCL reads high (no
slave stretches the clock); SDA reads low while the addressed slave
acknowledges a byte or sends a 0 bit, else high -- the pull-up, so an address
nobody answers gets no acknowledge.  The slave moves SDA only while SCL is
low, after a falling edge, as I2C wants.  A write transaction's bytes go to
the slave in one device.write() at the STOP or repeated START; a read
transaction's bytes come from device.read(1), one per byte the master clocks
in, until it answers a byte with no acknowledge.
"""
from i2c_scb import AckAll
from tm1650_decoder import PanelDecoder


class GpioI2cBus:
    """The slave side of a bit-banged I2C bus on pins `scl`, `sda` (GPIO numbers)."""
    LOG_FIRST = 64                              # transactions logged

    def __init__(self, sim, scl, sda, name="GPIO I2C"):
        self.sim, self.name = sim, name
        self.scl_offset, self.scl_bit = PanelDecoder._gpio_to_offset_bit(scl)
        self.sda_offset, self.sda_bit = PanelDecoder._gpio_to_offset_bit(sda)
        self.scl, self.sda = 1, 1               # the levels the CPU leaves on the lines (idle: high)
        self.state = 'IDLE'                     # IDLE, ADDR, WRITE, READ, IGNORE (no slave: wait for STOP)
        self.phase = 'bits'                     # bits; ack (the slave acknowledges); mack (the master does)
        self.nbits = 0                          # SCL rising edges in the byte so far
        self.byte = 0                           # the byte the master is sending
        self.out = 0                            # the byte the slave is sending
        self.reading = False                    # the address byte asked for a read
        self.master_ack = False
        self.device = None
        self.address = None
        self.written = bytearray()              # a write transaction's data, for device.write()
        self.transactions = 0

    # ---- the CPU side: pin levels --------------------------------------------
    def on_gpio_write(self, address, size, levels):
        offset = address & 0xFFF
        scl, sda = self.scl, self.sda
        if offset == self.scl_offset:
            scl = (levels >> self.scl_bit) & 1
        if offset == self.sda_offset:
            sda = (levels >> self.sda_bit) & 1
        if scl != self.scl:
            self.scl, self.sda = scl, sda
            self._rising() if scl else self._falling()
        elif sda != self.sda:
            self.sda = sda
            if scl and self._sda_out() is None:     # the CPU's own edge while SCL is high
                self._stop() if sda else self._start()

    def _line(self):
        """SDA as the bus has it: the CPU's level and the slave's, wired-AND."""
        out = self._sda_out()
        return self.sda & (1 if out is None else out)

    def _start(self):
        self._finish()                          # (a repeated START ends the transfer before it)
        self.state, self.phase, self.nbits, self.byte = 'ADDR', 'bits', 0, 0

    def _stop(self):
        self._finish()
        self.state = 'IDLE'

    def _finish(self):
        if self.state == 'WRITE' and self.device is not None and self.written:
            self.device.write(bytes(self.written))
            self._log("W", bytes(self.written))
        self.written = bytearray()
        self.device = None

    def _rising(self):
        if self.state in ('IDLE', 'IGNORE'):
            return
        if self.phase == 'bits':
            if self.state != 'READ':
                self.byte = ((self.byte << 1) | self._line()) & 0xFF
            self.nbits += 1
        elif self.phase == 'mack':
            self.master_ack = self._line() == 0

    def _falling(self):
        if self.state in ('IDLE', 'IGNORE'):
            return
        if self.phase == 'bits' and self.nbits == 8:
            if self.state == 'ADDR':
                self._address()
            elif self.state == 'WRITE':
                self.written.append(self.byte)
                self.phase = 'ack'
            else:
                self.phase = 'mack'             # the master acknowledges (or not) the byte it read
        elif self.phase == 'ack':
            self.phase, self.nbits, self.byte = 'bits', 0, 0
            if self.reading and self.state == 'ADDR':
                self.state = 'READ'
                self._load()
            elif self.state == 'ADDR':
                self.state = 'WRITE'
        elif self.phase == 'mack':
            self.phase, self.nbits = 'bits', 0
            if self.master_ack:
                self._load()
            else:
                self.state = 'IGNORE'           # the last byte: the master sends its STOP next

    def _address(self):
        address, self.reading = self.byte >> 1, bool(self.byte & 1)
        self.device = self.sim.i2c_devices.get(address) or (AckAll() if self.sim.i2c_ack_all else None)
        self.address = address
        if self.device is None:
            self.state = 'IGNORE'
            self._log("R" if self.reading else "W", b"", ack=False)
        else:
            self.phase = 'ack'

    def _load(self):
        """The next byte of a read, from the slave."""
        got = self.device.read(1) if self.device is not None else None
        if not got:
            self.state = 'IGNORE'
            return
        self.out = got[0]
        self._log("R", bytes(got[:1]))

    # ---- the slave side: what the firmware reads -----------------------------
    def _sda_out(self):
        """The level the slave drives on SDA (None: it leaves the line)."""
        if self.phase == 'ack' and self.state in ('ADDR', 'WRITE'):
            return 0
        if self.state == 'READ' and self.phase == 'bits':
            i = self.nbits - 1 if self.scl else self.nbits     # held until SCL falls, then the next bit
            if 0 <= i <= 7:
                return (self.out >> (7 - i)) & 1
        return None

    def di_override(self, di_offset, value):
        """Called by the simulator for every GPIO DI read: SCL reads high, SDA
        as the slave leaves it (released: high)."""
        if di_offset == self.scl_offset - 4:
            value |= 1 << self.scl_bit
        if di_offset == self.sda_offset - 4:
            out = self._sda_out()
            level = 1 if out is None else out
            value = value & ~(1 << self.sda_bit) | (level << self.sda_bit)
        return value

    def _log(self, kind, data, ack=True):
        self.transactions += 1
        if self.transactions <= self.LOG_FIRST:
            self.sim.log(f"[I2C] {self.name} {kind} 0x{self.address:02X}" + ("" if ack else " (no ACK)")
                         + (": " + data.hex(" ") if data else ""))
