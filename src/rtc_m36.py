"""
Model of the real-time clock of the ALi M3801 (S3811), reverse-engineered
from the SDK's RTC driver in the Comsat TE 1050 HD's application (dump.bin,
Libcore 8.1c): registers at 0xB8018A00 -- on the S3811 the driver takes
0xB8018F00 instead when the chip's revision is above 0x20001 (variant byte
non-zero), the same layout; the simulator's M3801 reads as variant 0.

  +00  write: load the time, bit 31 set (0x80353E9C): the year's two low
       bits (29-30, the leap-year cycle), month (25-28), day (20-24),
       weekday (17-19), hour (12-16), minute (6-11), second (0-5)
  +04  read: the running time in the same layout (0x80353F04: month, day,
       weekday, hour, minute, second)
  +0C  alarm status (bits 0-9, write 1 to clear; the ISR on interrupt 30)
       and enables (bits 16+), +10 + 4 * n alarm n -- not modelled (the
       registers are RAM)

The application keeps its calendar in two clocks of its own (the STC and
the UTC time, a tick task adds the seconds) but takes what it shows -- its
local time: the channel banner's date and time, the EPG's time line --
from this clock plus the time-zone offset: get_rtc_time (0x801DF39C)
combines the UTC clock's year with this register's month, day and time.
At start it loads it with the time saved in its settings (2010-11-01 when
that is not valid), and when a TDT / TOT section arrives with the stream's
time (set_UTC, 0x801DF254).  Read as 0 -- month 0, day 0 -- its MJD
arithmetic made 2025-11-28 00:00 of it, and the Comsat's programme guide
started at "01:00 28/11" whatever the stream said.

The clock runs with emulation time, like the firmware's own timers, from
the moment it is loaded; before the first load it reads 0.
"""

_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def pack(yy, month, day, weekday, hour, minute, second):
    """The register layout of a time (yy = the year's two low bits)."""
    return ((yy & 3) << 29) | ((month & 0xF) << 25) | ((day & 0x1F) << 20) | ((weekday & 7) << 17) \
        | ((hour & 0x1F) << 12) | ((minute & 0x3F) << 6) | (second & 0x3F)


def unpack(word):
    """(yy, month, day, weekday, hour, minute, second) of a register value."""
    return ((word >> 29) & 3, (word >> 25) & 0xF, (word >> 20) & 0x1F, (word >> 17) & 7,
            (word >> 12) & 0x1F, (word >> 6) & 0x3F, word & 0x3F)


def advance(fields, seconds):
    """The time `seconds` later: the time of day carries into the day, the
    day into the month (February has 29 days when the year's low bits are
    0), the month into the year's low bits; the weekday counts 1..7 (the
    SDK writes (MJD + 2) % 7 + 1, Monday = 1)."""
    yy, month, day, weekday, hour, minute, second = fields
    days, rem = divmod(second + 60 * (minute + 60 * hour) + int(seconds), 86400)
    hour, rem = divmod(rem, 3600)
    minute, second = divmod(rem, 60)
    for _ in range(days):
        weekday = weekday % 7 + 1
        length = 29 if month == 2 and yy == 0 else _DAYS[month - 1] if 1 <= month <= 12 else 31
        day += 1
        if day > length:
            day, month = 1, month + 1
            if month > 12:
                month, yy = 1, (yy + 1) & 3
    return yy, month, day, weekday, hour, minute, second


class Rtc:
    def __init__(self, sim, base=0x18A00):
        self.sim = sim
        self.base = base                    # offset in the device window
        self.loaded = None                  # (fields, emulation time of the load)
        self.loads = 0
        sim._mmio_on('w', self._w_load, base + 0x00, base + 0x03)
        sim._mmio_on('r', self._r_time, base + 0x04, base + 0x07)

    def _w_load(self, uc, access, address, size, value, user_data):
        """+00: a word with bit 31 loads the time."""
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        word = bytearray(uc.mem_read(0xB8000000 + self.base, 4))
        word[off:off + size] = value.to_bytes(size, 'little')
        word = int.from_bytes(word, 'little')
        if word >> 31:
            self.loaded = (unpack(word), self.sim._vtime())
            self.loads += 1
            if self.loads <= 8:
                yy, month, day, weekday, hour, minute, second = self.loaded[0]
                self.sim.log(f"[RTC] loaded {day:02d}/{month:02d} (year % 4 = {yy}, weekday {weekday}) "
                             f"{hour:02d}:{minute:02d}:{second:02d}")

    def fields(self):
        """The running time (yy, month, day, weekday, hour, minute, second), None before the first load."""
        if self.loaded is None:
            return None
        fields, t0 = self.loaded
        return advance(fields, self.sim._vtime() - t0)

    def _r_time(self, uc, access, address, size, value, user_data):
        """+04: the running time."""
        self.sim._device_access(uc)
        now = self.fields()
        if now is not None:
            uc.mem_write(0xB8000000 + self.base + 4, pack(*now).to_bytes(4, 'little'))

    def describe(self):
        now = self.fields()
        if now is None:
            return "RTC not loaded"
        yy, month, day, weekday, hour, minute, second = now
        return f"RTC {day:02d}/{month:02d} {hour:02d}:{minute:02d}:{second:02d} (weekday {weekday}, year % 4 = {yy})"
