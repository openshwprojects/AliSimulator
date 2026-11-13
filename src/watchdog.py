"""
The chip's watchdog (the SDK's dog_m3327e; 0xB8018500 on the M3801 / S3811):
a 32-bit counter at +0 that counts up while bit 2 of the control byte at +4
is set, at the memory clock divided by 2^(5+n) (n: control bits 0..1); in
reset mode (control bits 5..6, 0x60) the chip resets when the counter
overflows, with 0x10 an interrupt comes instead.  dog_m3327e_set_mode writes
the counter's start value, then the control byte; feeding writes the start
value again.  The M3801 loaders' 'reboot' arms it with 0xFFFFF000 / 0x67 (an
overflow within milliseconds); dump.bin and dump_maciej.bin run it from their
start (in the emulator 0xFDC3CB9F / 0x64, which is 8 s if the counter ran at
150 MHz / 32) and feed it about three times a second.  On a real revision-1
S3811 (the Comsat box) the counter measured 844,100 ticks/s with n = 0:
27 MHz / 32, the crystal's clock -- the model's default.

The model counts in emulated time and records every overflow in reset mode
(.overflows: (vtime of the overflow, the counter's start value, control));
it does not reset the machine (the emulator has no chip reset).  Opt-in:
sim.attach_watchdog(memory_clock_hz) after loadFile; until then the
registers are plain storage and the counter does not count.
"""

WRAP = 1 << 32


class Watchdog:
    SIZE = 8

    def __init__(self, sim, base=0x18500, memory_clock_hz=27_000_000):
        self.sim = sim
        self.base = base & 0xFFFFFF
        self.memory_clock_hz = memory_clock_hz
        self.value = 0                        # the counter at `since`
        self.since = None                     # emulated time it counts from (None: stopped)
        self.control = 0
        self.start_value = 0                  # the counter as last written
        self.overflows = []                   # (vtime, start value, control) of overflows in reset mode
        self.writes = []                      # (vtime, offset, size, value)
        sim._mmio_on('r', self._read, self.base, self.base + self.SIZE - 1)
        sim._mmio_on('w', self._write, self.base, self.base + self.SIZE - 1)
        sim.slice_services.append(self._service)

    def rate(self):
        """Counter ticks per emulated second."""
        return self.memory_clock_hz / (1 << (5 + (self.control & 3)))

    def _count(self, now):
        if self.since is None:
            return self.value
        return self.value + int((now - self.since) * self.rate())

    def _catch_up(self, now):
        """Past overflows recorded (in reset mode), the counter wrapped."""
        while self.since is not None:
            c = self._count(now)
            if c < WRAP:
                return
            at = self.since + (WRAP - self.value) / self.rate()
            if self.control & 0x60:
                self.overflows.append((round(at, 4), self.start_value, self.control))
            self.value, self.since = 0, at

    def count(self):
        """The counter now (as the guest would read it)."""
        now = self.sim._vtime()
        self._catch_up(now)
        return self._count(now) & 0xFFFFFFFF

    def due(self):
        """The emulated time of the counter's next overflow, None while it is stopped."""
        self._catch_up(self.sim._vtime())
        if self.since is None:
            return None
        return self.since + (WRAP - self.value) / self.rate()

    def _read(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        if off <= 3 and off + size > 0:
            word = self.count().to_bytes(4, "little")
            view = self.sim._mmio_view
            for i in range(size):
                if 0 <= off + i <= 3:
                    view[self.base + off + i] = word[off + i]

    def _write(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        now = self.sim._vtime()
        off = (address & 0xFFFFFF) - self.base
        value &= (1 << (8 * size)) - 1
        self.writes.append((round(now, 6), off, size, value))
        self._catch_up(now)
        if off == 0 and size == 4:                            # the counter
            self.value = self.start_value = value
            self.since = now if self.control & 0x04 else None
        elif off <= 4 < off + size:                           # the control byte
            new = (value >> (8 * (4 - off))) & 0xFF
            current = self._count(now)
            if new & 0x04:
                self.value, self.since = current, now         # (re)starts counting from here
            else:
                self.value, self.since = current, None        # stopped
            self.control = new

    def _service(self):
        if self.since is not None:
            self._catch_up(self.sim._vtime())
