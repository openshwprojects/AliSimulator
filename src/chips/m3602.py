"""
ALi M36xx generation (M3601E / M3602 / M3606: the Cabletech URZ0083 and
URZ0086, the Kruger&Matz KM0183 and KM0186, the Thomson THT501 and the
Ferguson Ariva T50 images), the SoCs before the M3801.  The CPU boots
straight from the flash window like the M3801's and the peripherals the
firmware uses first sit where the M3801's do (UART 0xB8018300, the I2C
masters 0xB8018200 / 0xB8018700 / 0xB8018B00, the GE 0xB800A000), and the
firmware wants an M36xx chip ID: the M3801's 0x3811 is not in its chip
tables, and an application that reads it starts over through the bootloader
(the URZ0083 every ~45 M instructions, the THT501 likewise).  The family's
own ID is 0x3602; a board whose SoC reads 0x3603 says so in its sidecar
(device.chipId, chips/base.py) -- the Opticum X110TS's application reboots
unless its chip code is 0x3603's, and the Cabletech, Kruger&Matz and
Thomson boxes read it too: their applications' USB host attach gives the
controller a base (0xB8032000 / 0xB8032400) only for 0x3603 or 0x3101, and
under 0x3602 the host's start ran into its assertion (an SDBBP, then a jump
to 0) right after the boot logo.  Under 0x3603 their bootloaders read the
flash with the quad I/O read 0xEB (simulator._SPI_READS), which the
simulator did not serve before: their chunk headers read as zeros
("malloc size: 0") and 0x3602 had looked like the only chip they booted on.

The Ferguson T50's bootloader probes its DDR at 0xA800AA68, 128 MB above the
first word: the RAM shows up again above its size here, as on a controller
that ignores the upper address bits.  (It still resets itself after its
flash checks -- see its sidecar.)

The M3606 (URZ0086 / KM0186, the X110TS) has a SEE co-processor, which its
bootloader starts and waits for: see.py runs the SEE's boot code for that
handshake.  The application then starts the SEE's own program, which runs
on a second core (see.SeeCore) and answers the application's remote calls.

The M3601E boxes decode a boot logo from the flash before anything else and
wait until their MPEG decoder reports the first picture shown: the video
engine's completion and the video output's field interrupts are
video_m36.py's.

The chip ID 0x3603 is the SDK's C3603, whose product -- bits 8..11 of the
chip ID word -- picks a row of its feature table (product_feature); byte 4
of the row enables its DVB-S2 demodulator, which the Opticum X110TS's
application asks for by name (NIM_S3501_0) and by chip ID (S3501) once its
OSD is up, in a check of its own (0x801B994C).  With the product bits clear
(product 0, the one row without the demodulator) and no demodulator on the
I2C bus the check failed, and a task of the application cleared the OSD
layer's enable bit (0xB8006300 bit 0) about ten times a second: its screen
stayed black although it drew its channel banner.  A C3603 board therefore
reads C3603_PRODUCT in those bits and has its S3501 on the bus.

Recognised by the chunk chain: the HDCPKey chunk's version "Demo s3602"
(the M3801 images say "Demo M3801"), a maincode chunk named after the
SDK's M3602 / M3606 demo projects ("Demo M3602", "Demo M3606",
"M3606 2Tuner"), or a main-code chunk whose version names the chip (the
Opticum satellite updates: "M3601S", "M3606 2Tuner").
"""
import ctypes

from unicorn import UC_PROT_ALL

from demods import S3501

from .base import ChipFamily, chunk_chain
from .see import SeeStart

RAM_WINDOW_END = 0x0F000000         # the flash window starts here (simulator.py)
C3603 = 0x3603                      # the chip ID of the twin-tuner satellite boards (the X110TS)
# (the SDK's sys_ic_get_c3603_product: bits 8..11 = 0xC -> product 0xE, 5 or 7 -> 0xB, others -> 0.
# Every product but 0 has the DVB-S2 demodulator; which one the X110TS's chip is, is not known.)
C3603_PRODUCT = 0x0500
# (the C3603's DVB-S2 demodulator is demods.S3501, at 0x33 on the first I2C master)


class M3602(ChipFamily):
    name = "M3602"
    chip_id = 0x3602
    # (its MPEG decoder, the SDK's vdec_s3601, keeps the VLD's bit offset at +0x28 of the
    # video engine: vdec_hal_vld_config_data writes the start, vdec_hal_vld_get_offset
    # reads it back.  Read as the M3801's status word, with bits 8..25 cleared, the
    # offset went back and the URZ0086 V1.1.1's SEE program stopped at its assertion
    # that the video buffer's read pointer only moves on, ~85 M instructions in.)
    ve_status = False

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
        # the M3606's DMA engine at 0xB800F200, which the SEE's video decoder feeds, with its
        # start codes (m3821.DmaRings); the SEE core gets it too (core_devices, see.SeeStart._wire)
        from .m3821 import DmaRings
        self.dma = DmaRings(sim, base=0xF200, start_codes=True)
        # The M3606's SEE co-processor: its start handshake (see.py)
        self.see = SeeStart(sim)
        # the transport-stream demultiplexer DMX0 at 0xB8022000, as on the M3801 (dmx_m36.py)
        from dmx_m36 import Demux
        self.dmx = Demux(sim)
        # the video engine's completion and the video output's field interrupts: a boot logo
        # gets decoded and shown (video_m36.py); on the M3606 the SEE drives them
        from video_m36 import VideoEngine, VideoOutput
        self.video_engine = VideoEngine(sim)
        self.video_output = VideoOutput(sim)
        self.core_devices = (self.dma, self.video_engine, self.video_output)
        # (The graphics engine is the M3801's: base 0xB800A000 and
        # interrupt-controller line 4.  The Thomson THT501's GE attach pairs
        # that base with "IRQ 12", which is the OS's interrupt number -- the
        # controller line plus 8, as the IR receiver's line 19 is OS IRQ 27 --
        # so nothing differs; raising line 12 instead sends its dispatcher to
        # its fatal path at the first GE command.)

    def variant(self):
        return C3603_PRODUCT if self.chip_id == C3603 else self.chip_variant

    def write_chip_id(self):
        """The board's chip ID word, and on a C3603 a fresh S3501 on the I2C
        bus (a board of another chip ID loaded after it has none)."""
        super().write_chip_id()
        self._remove_demod()
        if self.chip_id == C3603:
            self.sim.i2c_devices[S3501.ADDRESS] = S3501()

    def _remove_demod(self):
        if isinstance(self.sim.i2c_devices.get(S3501.ADDRESS), S3501):
            del self.sim.i2c_devices[S3501.ADDRESS]

    def uninstall(self):
        for address, size in self._ram_mirrors():
            self.sim.mu.mem_unmap(address, size)
        self._remove_demod()
