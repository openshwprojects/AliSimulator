"""
ALi M3821 family (M3821 / M3822P, the DVB-T2 generation: the Opticum Blue
R265 Lite dump).  The flash has the same NCRC chunk chain as the M3801's and
is memory-mapped at 0xAFC00000 like there, but the bootloader chunk is built
for an on-chip boot ROM:

  * the chunk's version string is "M3821b-0.1.0" (that is how the family is
    recognised);
  * offset 0x470.. holds a descriptor table the boot ROM interprets (a
    register script: clock registers at 0xB8001000.., the DDR controller at
    0xB803E02C..), not code;
  * the bootloader itself starts at offset 0x800 and expects to run from a
    boot SRAM at physical 0x1FE00000 (KSEG0 0x9FE00000: its stack sits at
    0x9FE04000 and it jumps to 0x9FE02488), so the boot ROM copies the
    bootloader area there and enters at 0x9FE00800.

Once there it prints "NOR1" on the UART (the same 16550 at 0xB8018300),
programs the clock tree, trains the DDR controller (0xB803E000..) and copies
the next stage from the flash window into RAM (its "HEAD" record at flash
offset 0x250: load address 0xA1000000).  The simulator's RAM needs no
training, so the DDR model only answers the status and pattern words the
training loop checks (DdrTraining).
"""
import ctypes

from unicorn import UC_PROT_ALL
from unicorn.mips_const import UC_MIPS_REG_PC

from .base import ChipFamily

SRAM_PHYS = 0x1FE00000          # the boot SRAM the boot ROM copies the bootloader into
SRAM_SIZE = 0x100000
BOOT_COPY = 0x60000             # the bootloader area of the flash (its chunk: 0..0x5FE00)
ENTRY = 0x80000000 + SRAM_PHYS + 0x800


class DdrTraining:
    """The DDR controller's training status at 0xB803E08C.. and the pattern
    capture words at 0xB803E090.. (one 32-byte block per byte lane) the
    bootloader reads while it sweeps the delay taps of each lane
    (0xB803E02E + lane, 0xB803E082 + lane, 0xB803E034 / 38, applied with bit 7
    of 0xB803E03B / 3F): it keeps a setting when the status says locked and the
    captured words are its test patterns (bootloader 0x9FE00B20; lane 0 is
    compared against different words than the other lanes).  The simulator's
    RAM always reads back what was written, so the model is the answers only."""
    STATUS = 0x3E08C            # bits 8..0 = 2 * delay taps, bits 31..30 = locked
    CAPTURE = 0x3E090           # + lane * 0x20 + word * 4
    LANES = 4
    TAPS = 32
    PATTERNS_LANE0 = (0x0FF00FF0, 0xFF00FF00, 0x00FF00FF, 0xF00FF00F,
                      0x0FF00FF0, 0x00FF00FF, 0xFF00FF00, 0x0FF00FF0)
    PATTERNS_OTHER = (0xA55AA55A, 0xFF00FF00, 0x00FF00FF, 0x5AA55AA5,
                      0xA55AA55A, 0x00FF00FF, 0xFF00FF00, 0xA55AA55A)

    def __init__(self, sim):
        self.sim = sim
        sim._mmio_on('r', self._read_status, self.STATUS, self.STATUS + 3)
        sim._mmio_on('r', self._read_capture, self.CAPTURE, self.CAPTURE + self.LANES * 0x20 - 1)

    def _read_status(self, uc, access, address, size, value, user_data):
        word = 0xC0000000 | (2 * self.TAPS)
        uc.mem_write(0xB8000000 + self.STATUS, word.to_bytes(4, 'little'))

    def _read_capture(self, uc, access, address, size, value, user_data):
        off = (address & 0xFFFFFF) - self.CAPTURE
        lane, word = off >> 5, (off & 0x1F) >> 2
        patterns = self.PATTERNS_LANE0 if lane == 0 else self.PATTERNS_OTHER
        uc.mem_write(address & ~3, patterns[word].to_bytes(4, 'little'))


class M3821(ChipFamily):
    name = "M3821"
    chip_id = 0x3821

    @classmethod
    def matches(cls, image):
        return bytes(image[0x20:0x25]) == b"M3821"      # the bootloader chunk's version string

    def install(self):
        super().install()
        sim = self.sim
        # The boot SRAM, in place of the flash mirror the M3801 shows there
        self.sram = ctypes.create_string_buffer(SRAM_SIZE)
        ptr = ctypes.addressof(self.sram)
        for seg in (0x00000000, 0x80000000, 0xA0000000):
            sim.mu.mem_unmap(seg + SRAM_PHYS, SRAM_SIZE)
            sim.mu.mem_map_ptr(seg + SRAM_PHYS, SRAM_SIZE, UC_PROT_ALL, ptr)
        self.ddr = DdrTraining(sim)

    def start(self):
        """What the boot ROM does: the bootloader area into the SRAM, enter it."""
        sim = self.sim
        ctypes.memmove(ctypes.addressof(self.sram), bytes(sim.rom_image[:BOOT_COPY]), BOOT_COPY)
        sim._rescan_cp0_sites(self.code_ranges())
        sim.mu.reg_write(UC_MIPS_REG_PC, ENTRY)

    def code_ranges(self):
        return [(0x80000000 + SRAM_PHYS, BOOT_COPY)]
