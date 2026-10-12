"""
ALi M36xx generation (M3601E / M3602 / M3606: the Cabletech URZ0083 and
URZ0086, the Kruger&Matz KM0183 and KM0186, the Thomson THT501 and the
Ferguson Ariva T50 images), the SoCs before the M3801.  The CPU boots
straight from the flash window like the M3801's and the peripherals the
firmware uses first sit where the M3801's do (UART 0xB8018300, the I2C
masters 0xB8018200 / 0xB8018700 / 0xB8018B00, the GE 0xB800A000), but the
firmware wants the chip ID 0x3602: the M3801's 0x3811 is not in its chip
tables, and an application that reads it starts over through the bootloader
(the URZ0083 every ~45 M instructions, the THT501 likewise), while with
0x3602 both keep running.  (Their tables also know 0x3603, for which the
URZ0083 moves its SPI flash registers to 0xB802E098 and prints nothing at
all within 160 M instructions: not this chip.)  A board whose SoC reads
0x3603 says so in its sidecar (device.chipId, chips/base.py): the Opticum
X110TS's application maps the chip ID to a chip code and reboots unless it
is 0x3603's, while the Cabletech URZ0086, another "M3606 2Tuner" build,
boots with 0x3602 -- under 0x3603 its bootloader polls a register at
0xB801841C, which nothing models, for ever.

The Ferguson T50's bootloader probes its DDR at 0xA800AA68, 128 MB above the
first word: the RAM shows up again above its size here, as on a controller
that ignores the upper address bits.  (It still resets itself after its
flash checks -- see its sidecar.)

The M3606 (URZ0086 / KM0186, the X110TS) has a SEE co-processor, which its
bootloader starts and waits for: see.py runs the SEE's boot code for that
handshake.  The application then starts the SEE's own program, which runs
on a second core (see.SeeCore) and answers the application's remote calls.

Recognised by the chunk chain: the HDCPKey chunk's version "Demo s3602"
(the M3801 images say "Demo M3801"), a maincode chunk named after the
SDK's M3602 / M3606 demo projects ("Demo M3602", "Demo M3606",
"M3606 2Tuner"), or a main-code chunk whose version names the chip (the
Opticum satellite updates: "M3601S", "M3606 2Tuner").
"""
import ctypes

from unicorn import UC_PROT_ALL

from .base import ChipFamily, chunk_chain
from .see import SeeStart

RAM_WINDOW_END = 0x0F000000         # the flash window starts here (simulator.py)


class M3602(ChipFamily):
    name = "M3602"
    chip_id = 0x3602

    @classmethod
    def matches(cls, image):
        for _offset, name, version in chunk_chain(image):
            if name == "HDCPKey" and version.startswith("Demo s3602"):
                return True
            if name == "maincode" and version.startswith(("Demo M3602", "Demo M3606", "M3606")):
                return True
            # the Opticum / Globo satellite updates name their main-code chunk by a number and
            # put the chip in its version ("M3601S", "M3606 2Tuner"; the Globo HD-XS2's M3503,
            # named in its bootloader's version, is m3503.py)
            if version.startswith(("M3601", "M3606")):
                return True
        return False

    def _ram_mirrors(self):
        """(address, size) of the RAM's mirrors above its size, up to the flash window."""
        sim = self.sim
        return [(seg + phys, min(sim.ram_size, RAM_WINDOW_END - phys))
                for phys in range(sim.ram_size, RAM_WINDOW_END, sim.ram_size)
                for seg in (0x00000000, 0x80000000, 0xA0000000)]

    def install(self):
        super().install()
        sim = self.sim
        # The RAM again above its size, up to the flash window (the T50's DDR probe)
        ptr = ctypes.addressof(sim.ram_buffer)
        for address, size in self._ram_mirrors():
            sim.mu.mem_map_ptr(address, size, UC_PROT_ALL, ptr)
        # The M3606's SEE co-processor: its start handshake (see.py)
        self.see = SeeStart(sim)
        # the transport-stream demultiplexer DMX0 at 0xB8022000, as on the M3801 (dmx_m36.py)
        from dmx_m36 import Demux
        self.dmx = Demux(sim)
        # (The graphics engine is the M3801's: base 0xB800A000 and
        # interrupt-controller line 4.  The Thomson THT501's GE attach pairs
        # that base with "IRQ 12", which is the OS's interrupt number -- the
        # controller line plus 8, as the IR receiver's line 19 is OS IRQ 27 --
        # so nothing differs; raising line 12 instead sends its dispatcher to
        # its fatal path at the first GE command.)

    def uninstall(self):
        for address, size in self._ram_mirrors():
            self.sim.mu.mem_unmap(address, size)
