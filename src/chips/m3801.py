"""
ALi M3801 (the DVB-T boxes: Comsat TE 1050 HD, Opticum N2, Globo N3, the
Cabletech, Strong and Ferguson dumps): the CPU boots straight from the flash
window, reset vector 0xBFC00000 / SYS_FLASH_BASE_ADDR 0xAFC00000, and the
firmware identifies the silicon as an S3811 (chip ID 0x3811).  Everything
simulator.py models by default is this family's, so nothing is added here.
"""
from .base import ChipFamily


class M3801(ChipFamily):
    name = "M3801"
    chip_id = 0x3811

    @classmethod
    def matches(cls, image):
        return True                 # the default family (see chips.detect)
