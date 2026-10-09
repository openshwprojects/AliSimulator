"""The interface of a chip family (see chips/__init__.py)."""
from unicorn.mips_const import UC_MIPS_REG_PC


class ChipFamily:
    """What a family adds to the common simulator: override what differs."""
    name = "ALi"
    chip_id = 0x0000            # the 16-bit chip ID at 0xB8000002 the firmware's chip-ID function reads

    def __init__(self, sim):
        self.sim = sim

    @classmethod
    def matches(cls, image):
        """Whether a flash image (bytes) is this family's."""
        return False

    def install(self):
        """Memory and devices of this family, on top of the common ones; called
        once when the simulator (or loadFile) switches to the family."""
        self.sim.poke(0xB8000002, self.chip_id.to_bytes(2, 'little'))

    def start(self):
        """The reset state once an image is in the flash: where the CPU starts
        (after whatever the chip's boot ROM did before handing over)."""
        self.sim.mu.reg_write(UC_MIPS_REG_PC, self.sim.base_addr)

    def code_ranges(self):
        """Memory besides RAM and flash that holds code: [(address, length)] in the
        0x80000000 view, scanned for CP0 instruction sites like RAM is."""
        return []
