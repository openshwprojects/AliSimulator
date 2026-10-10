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
all within 160 M instructions: not this chip.)

The Ferguson T50's bootloader probes its DDR at 0xA800AA68, 128 MB above the
first word: the RAM shows up again above its size here, as on a controller
that ignores the upper address bits.  (It still resets itself after its
flash checks -- see its sidecar.)

Recognised by the chunk chain: the HDCPKey chunk's version "Demo s3602"
(the M3801 images say "Demo M3801"), or a maincode chunk named after the
SDK's M3602 / M3606 demo projects ("Demo M3602", "Demo M3606",
"M3606 2Tuner").
"""
import ctypes

from unicorn import UC_PROT_ALL, UcError

from .base import ChipFamily, chunk_chain

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
        return False

    def install(self):
        super().install()
        sim = self.sim
        # The RAM again above its size, up to the flash window (the T50's DDR probe)
        ptr = ctypes.addressof(sim.ram_buffer)
        for phys in range(sim.ram_size, RAM_WINDOW_END, sim.ram_size):
            size = min(sim.ram_size, RAM_WINDOW_END - phys)
            for seg in (0x00000000, 0x80000000, 0xA0000000):
                try:
                    sim.mu.mem_map_ptr(seg + phys, size, UC_PROT_ALL, ptr)
                except UcError:
                    pass            # mapped when this simulator had the family before
